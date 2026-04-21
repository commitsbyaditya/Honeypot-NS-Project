"""
Unified Security Control Center
===============================

Implements a single workflow UI for:
- Attack simulation orchestration
- Attack data exploration and export
- Model training with live progress
- Dashboard launch and handoff
"""

from __future__ import annotations

import ctypes
import os
import subprocess
import sys
import time
import webbrowser
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import List

import pandas as pd
import streamlit as st


# -----------------------------------------------------------------------------
# Paths
# -----------------------------------------------------------------------------
ROOT_DIR = Path(__file__).resolve().parent.parent
DATA_CSV = ROOT_DIR / "data" / "attack_logs.csv"
SIM_RUNNER = ROOT_DIR / "run_all_simulators.py"
TRAIN_SCRIPT = ROOT_DIR / "ml" / "train_model_multi.py"
DASHBOARD_SCRIPT = ROOT_DIR / "dashboard" / "dashboard_multi.py"
MODEL_FILE = ROOT_DIR / "models" / "attack_model.pkl"
ENCODER_FILE = ROOT_DIR / "models" / "label_encoder.pkl"


# -----------------------------------------------------------------------------
# App state
# -----------------------------------------------------------------------------
class ViewState(str, Enum):
    HOME = "home"
    RUNNING_SIMULATION = "running_simulation"
    POST_SIMULATION = "post_simulation"
    DATA_VIEW = "data_view"
    RUNNING_TRAINING = "running_training"
    POST_TRAINING = "post_training"


@dataclass
class CheckResult:
    name: str
    ok: bool
    detail: str


PHASE_PROGRESS = {
    "init": 5,
    "ssh": 20,
    "portscan": 40,
    "dns": 60,
    "icmp": 80,
    "arp": 90,
    "finalizing": 97,
    "done": 100,
}

PHASE_LABELS = {
    "init": "Initializing Simulation Engine",
    "ssh": "SSH Attack Simulation",
    "portscan": "Port Scan Simulation",
    "dns": "DNS Attack Simulation",
    "icmp": "ICMP Attack Simulation",
    "arp": "ARP Attack Simulation",
    "finalizing": "Finalizing and Saving Outputs",
    "done": "Simulation Completed",
}

PHASE_SUBTEXT = {
    "init": "Preparing process and prerequisites.",
    "ssh": "Credential probing and command behavior generation in progress.",
    "portscan": "Reconnaissance sweep behavior is being replayed.",
    "dns": "Query storm, tunneling, and amplification behaviors are running.",
    "icmp": "Flood and oversized ping traffic generation phase.",
    "arp": "Layer-2 spoofing and poisoning pattern generation phase.",
    "finalizing": "Collecting results and wrapping up simulation session.",
    "done": "Simulation finished successfully.",
}

TRAIN_PROGRESS = {
    "prep": 8,
    "load": 20,
    "features": 35,
    "labels": 48,
    "fit": 68,
    "evaluate": 84,
    "save": 94,
    "done": 100,
}

TRAIN_LABELS = {
    "prep": "Initializing Training Pipeline",
    "load": "Loading Attack Dataset",
    "features": "Extracting Feature Matrix",
    "labels": "Generating and Encoding Labels",
    "fit": "Training Random Forest Model",
    "evaluate": "Evaluating Model Quality",
    "save": "Saving Model Artifacts",
    "done": "Training Completed",
}

TRAIN_SUBTEXT = {
    "prep": "Validating files and preparing runtime.",
    "load": "Reading attack records from selected dataset.",
    "features": "Building numerical feature vectors for ML.",
    "labels": "Applying attack labeling strategy.",
    "fit": "Model fitting is in progress.",
    "evaluate": "Computing metrics and validation outputs.",
    "save": "Persisting model and label encoder.",
    "done": "Training finished successfully.",
}


ANIMATION_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700&family=Fraunces:opsz,wght@9..144,500;9..144,600&display=swap');

:root {
    --bg-top: #f4f0e8;
    --bg-bottom: #e2ddd2;
    --ink: #21303d;
    --muted: #5f6c78;
    --panel-top: #fbf8f2;
    --panel-bottom: #dfd7ca;
    --panel-edge: #c6bbac;
    --accent: #25668a;
    --accent-strong: #1a4761;
}

.stApp {
    background:
        radial-gradient(1200px 520px at 0% -10%, rgba(255, 255, 255, 0.85) 0%, rgba(255, 255, 255, 0.0) 60%),
        radial-gradient(900px 500px at 100% 0%, rgba(197, 217, 228, 0.5) 0%, rgba(197, 217, 228, 0.0) 62%),
        linear-gradient(180deg, var(--bg-top) 0%, var(--bg-bottom) 100%);
    color: var(--ink);
    font-family: "Space Grotesk", "Segoe UI", sans-serif;
}

.block-container {
    max-width: 1200px;
    padding-top: 1.4rem;
    padding-bottom: 2rem;
}

h1, h2, h3, h4 {
    color: var(--ink);
    letter-spacing: 0.01em;
}

div[data-testid="stAlert"] {
    border-radius: 14px;
    border: 1px solid #cec2b2;
    background: linear-gradient(180deg, #f9f6f0 0%, #e9e2d7 100%);
    box-shadow:
        inset 0 1px 0 rgba(255, 255, 255, 0.92),
        0 5px 15px rgba(59, 47, 37, 0.11);
}

div[data-testid="stExpander"] {
    border: 1px solid #cdbfae;
    border-radius: 14px;
    background: linear-gradient(180deg, #f8f4ee 0%, #e5ddcf 100%);
    box-shadow:
        inset 0 1px 0 rgba(255, 255, 255, 0.9),
        0 6px 14px rgba(73, 57, 44, 0.11);
}

.stButton > button,
.stDownloadButton > button {
    border-radius: 12px;
    border: 1px solid #adb5bd;
    background: linear-gradient(180deg, #fefefe 0%, #d8dde3 100%);
    color: #1f2e3b;
    font-weight: 600;
    box-shadow:
        inset 0 1px 0 rgba(255, 255, 255, 0.95),
        inset 0 -1px 0 rgba(33, 48, 61, 0.15),
        0 3px 0 #b3bcc5,
        0 10px 16px rgba(54, 66, 78, 0.2);
    transition: all 0.12s ease-in-out;
}

.stButton > button:hover,
.stDownloadButton > button:hover {
    filter: saturate(1.06);
    transform: translateY(-1px);
}

.stButton > button:active,
.stDownloadButton > button:active {
    transform: translateY(2px);
    box-shadow:
        inset 0 2px 6px rgba(0, 0, 0, 0.22),
        0 1px 0 #b3bcc5;
}

.stButton > button[kind="primary"] {
    border: 1px solid #205473;
    background: linear-gradient(180deg, #4a90b6 0%, #255f82 100%);
    color: #f8fbfe;
    box-shadow:
        inset 0 1px 0 rgba(188, 228, 249, 0.7),
        inset 0 -1px 0 rgba(16, 43, 60, 0.55),
        0 3px 0 #1c4d69,
        0 10px 16px rgba(31, 69, 95, 0.34);
}

.stTextInput input,
.stNumberInput input,
.stSelectbox [data-baseweb="select"] > div,
.stMultiSelect [data-baseweb="select"] > div,
.stSlider {
    border-radius: 12px !important;
    border: 1px solid #c4b9a8 !important;
    background: linear-gradient(180deg, #fffefb 0%, #eee7dc 100%) !important;
    box-shadow:
        inset 0 1px 3px rgba(50, 38, 26, 0.18),
        0 1px 0 rgba(255, 255, 255, 0.84) !important;
}

div[data-testid="stDataFrame"] {
    border: 1px solid #c8bcae;
    border-radius: 14px;
    overflow: hidden;
    box-shadow:
        inset 0 1px 0 rgba(255, 255, 255, 0.9),
        0 12px 20px rgba(57, 44, 33, 0.14);
}

.product-shell {
    border-radius: 18px;
    border: 1px solid var(--panel-edge);
    background: linear-gradient(180deg, var(--panel-top) 0%, var(--panel-bottom) 100%);
    box-shadow:
        inset 0 1px 0 rgba(255, 255, 255, 0.92),
        inset 0 -1px 0 rgba(69, 54, 41, 0.18),
        0 18px 28px rgba(69, 54, 41, 0.18);
    padding: 1rem 1.15rem;
    margin-bottom: 1rem;
}

.product-bar {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 1rem;
    flex-wrap: wrap;
}

.brand-title {
    margin: 0;
    font-family: "Fraunces", Georgia, serif;
    font-size: 1.65rem;
    line-height: 1.2;
    color: #1a2d3c;
}

.brand-sub {
    margin: 0.25rem 0 0 0;
    color: var(--muted);
    font-size: 0.95rem;
}

.product-pills {
    display: flex;
    gap: 0.45rem;
    flex-wrap: wrap;
}

.product-pill {
    border-radius: 999px;
    padding: 0.32rem 0.68rem;
    border: 1px solid #b8c3cd;
    background: linear-gradient(180deg, #fefefe 0%, #d7dde3 100%);
    color: #23384a;
    font-size: 0.8rem;
    font-weight: 600;
    box-shadow:
        inset 0 1px 0 rgba(255, 255, 255, 0.9),
        0 3px 7px rgba(57, 71, 85, 0.18);
}

.action-kicker {
    color: #334959;
    font-size: 0.85rem;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    margin-bottom: 0.25rem;
    font-weight: 700;
}

.action-copy {
    color: #5b6974;
    font-size: 0.93rem;
    margin-bottom: 0.7rem;
}

.phase-card {
    border: 1px solid #b8aa95;
    border-radius: 12px;
    padding: 14px 18px;
    margin-bottom: 12px;
    background: linear-gradient(180deg, #f9f5ef 0%, #e7dfd2 100%);
    box-shadow:
        inset 0 1px 0 rgba(255, 255, 255, 0.9),
        0 8px 15px rgba(71, 56, 43, 0.15);
}
.phase-title {
    font-size: 1.05rem;
    font-weight: 600;
    margin-bottom: 8px;
    color: #203646;
}
.phase-sub {
    opacity: 0.95;
    font-size: 0.92rem;
    color: #5d6b78;
}
.phase-row {
    display: flex;
    align-items: center;
    gap: 10px;
}
.phase-orb {
    width: 14px;
    height: 14px;
    border-radius: 50%;
    animation: pulse 1.4s infinite ease-in-out;
}
.phase-bar {
    margin-top: 10px;
    height: 6px;
    border-radius: 8px;
    background: rgba(104, 90, 70, 0.14);
    overflow: hidden;
}
.phase-bar > span {
    display: block;
    height: 100%;
    width: 38%;
    animation: sweep 1.2s infinite linear;
}
.phase-ssh .phase-orb, .phase-ssh .phase-bar > span { background: #2f7baa; }
.phase-portscan .phase-orb, .phase-portscan .phase-bar > span { background: #b87733; }
.phase-dns .phase-orb, .phase-dns .phase-bar > span { background: #1f8a75; }
.phase-icmp .phase-orb, .phase-icmp .phase-bar > span { background: #bc5d20; }
.phase-arp .phase-orb, .phase-arp .phase-bar > span { background: #b03d4d; }
.phase-init .phase-orb, .phase-init .phase-bar > span,
.phase-finalizing .phase-orb, .phase-finalizing .phase-bar > span,
.phase-done .phase-orb, .phase-done .phase-bar > span { background: #685c9f; }
.phase-prep .phase-orb, .phase-prep .phase-bar > span { background: #2f7baa; }
.phase-load .phase-orb, .phase-load .phase-bar > span { background: #1f8a75; }
.phase-features .phase-orb, .phase-features .phase-bar > span { background: #6f5c95; }
.phase-labels .phase-orb, .phase-labels .phase-bar > span { background: #b97a21; }
.phase-fit .phase-orb, .phase-fit .phase-bar > span { background: #b55037; }
.phase-evaluate .phase-orb, .phase-evaluate .phase-bar > span { background: #3e875f; }
.phase-save .phase-orb, .phase-save .phase-bar > span { background: #2a877f; }

@media (max-width: 900px) {
    .product-bar {
        flex-direction: column;
        align-items: flex-start;
    }
    .brand-title {
        font-size: 1.4rem;
    }
}

@keyframes pulse {
    0% { transform: scale(0.85); opacity: 0.65; }
    50% { transform: scale(1.15); opacity: 1; }
    100% { transform: scale(0.85); opacity: 0.65; }
}

@keyframes sweep {
    from { margin-left: -40%; }
    to { margin-left: 100%; }
}
</style>
"""


# -----------------------------------------------------------------------------
# Capability / admin helpers
# -----------------------------------------------------------------------------
def is_admin() -> bool:
    """Return True when process has elevated/admin privileges."""
    try:
        if os.name == "nt":
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        return os.geteuid() == 0
    except Exception:
        return False


def relaunch_as_admin() -> bool:
    """
    Relaunch this Streamlit app elevated (Windows only).

    Returns True when elevation command was accepted by the shell.
    Returns False when unsupported or denied.
    """
    if os.name != "nt":
        return False

    python_exe = sys.executable
    script_path = Path(__file__).resolve()
    args = f'-m streamlit run "{script_path}"'

    # ShellExecuteW with "runas" triggers UAC prompt.
    rc = ctypes.windll.shell32.ShellExecuteW(
        None,
        "runas",
        python_exe,
        args,
        str(ROOT_DIR),
        1,
    )
    return rc > 32


# -----------------------------------------------------------------------------
# Startup checks
# -----------------------------------------------------------------------------
def run_prerequisite_checks() -> List[CheckResult]:
    checks: List[CheckResult] = []

    checks.append(
        CheckResult(
            name="Simulation runner",
            ok=SIM_RUNNER.exists(),
            detail=str(SIM_RUNNER),
        )
    )
    checks.append(
        CheckResult(
            name="Training script",
            ok=TRAIN_SCRIPT.exists(),
            detail=str(TRAIN_SCRIPT),
        )
    )
    checks.append(
        CheckResult(
            name="Dashboard script",
            ok=DASHBOARD_SCRIPT.exists(),
            detail=str(DASHBOARD_SCRIPT),
        )
    )
    checks.append(
        CheckResult(
            name="Data CSV",
            ok=DATA_CSV.exists(),
            detail=str(DATA_CSV),
        )
    )

    model_ok = MODEL_FILE.exists() and ENCODER_FILE.exists()
    checks.append(
        CheckResult(
            name="Trained model artifacts",
            ok=model_ok,
            detail=f"{MODEL_FILE} | {ENCODER_FILE}",
        )
    )

    return checks


# -----------------------------------------------------------------------------
# Session state setup
# -----------------------------------------------------------------------------
def init_state() -> None:
    if "view_state" not in st.session_state:
        st.session_state.view_state = ViewState.HOME

    if "return_state" not in st.session_state:
        st.session_state.return_state = ViewState.HOME

    if "startup_checks" not in st.session_state:
        st.session_state.startup_checks = run_prerequisite_checks()

    if "admin_mode" not in st.session_state:
        st.session_state.admin_mode = is_admin()

    if "elevation_attempted" not in st.session_state:
        st.session_state.elevation_attempted = False

    if "elevation_status" not in st.session_state:
        st.session_state.elevation_status = "not_attempted"

    if "sim_started" not in st.session_state:
        st.session_state.sim_started = False

    if "sim_finished" not in st.session_state:
        st.session_state.sim_finished = False

    if "sim_success" not in st.session_state:
        st.session_state.sim_success = False

    if "sim_exit_code" not in st.session_state:
        st.session_state.sim_exit_code = None

    if "sim_phase" not in st.session_state:
        st.session_state.sim_phase = "init"

    if "sim_logs" not in st.session_state:
        st.session_state.sim_logs = []

    if "sim_progress" not in st.session_state:
        st.session_state.sim_progress = 0

    if "train_dataset_path" not in st.session_state:
        st.session_state.train_dataset_path = str(DATA_CSV)

    if "train_started" not in st.session_state:
        st.session_state.train_started = False

    if "train_finished" not in st.session_state:
        st.session_state.train_finished = False

    if "train_success" not in st.session_state:
        st.session_state.train_success = False

    if "train_exit_code" not in st.session_state:
        st.session_state.train_exit_code = None

    if "train_phase" not in st.session_state:
        st.session_state.train_phase = "prep"

    if "train_logs" not in st.session_state:
        st.session_state.train_logs = []

    if "train_progress" not in st.session_state:
        st.session_state.train_progress = 0

    if "dashboard_launch_attempted" not in st.session_state:
        st.session_state.dashboard_launch_attempted = False

    if "dashboard_launch_success" not in st.session_state:
        st.session_state.dashboard_launch_success = False

    if "dashboard_url" not in st.session_state:
        st.session_state.dashboard_url = "http://localhost:8502"

    if "dashboard_pid" not in st.session_state:
        st.session_state.dashboard_pid = None


# -----------------------------------------------------------------------------
# Rendering helpers
# -----------------------------------------------------------------------------
def render_header() -> None:
    st.markdown(
        """
        <div class="product-shell">
            <div class="product-bar">
                <div>
                    <h1 class="brand-title">Sentinel Security Console</h1>
                    <p class="brand-sub">Enterprise workflow for simulation, data operations, model training, and executive monitoring.</p>
                </div>
                <div class="product-pills">
                    <span class="product-pill">Customer Edition</span>
                    <span class="product-pill">Live Operations</span>
                    <span class="product-pill">Skeuomorphic UI</span>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_capability_banner() -> None:
    if st.session_state.admin_mode:
        st.success("Capability mode: Full Mode (Admin)")
    else:
        st.warning("Capability mode: Limited Mode (No Admin). ARP/ICMP dependent flows may be skipped.")


def render_startup_checks() -> None:
    checks: List[CheckResult] = st.session_state.startup_checks
    ok_count = sum(1 for c in checks if c.ok)
    total = len(checks)

    st.info(f"Startup checks complete: {ok_count}/{total} passed")

    if st.button("Refresh prerequisite checks", use_container_width=True):
        st.session_state.startup_checks = run_prerequisite_checks()
        st.rerun()

    with st.expander("View prerequisite checks", expanded=False):
        for item in checks:
            if item.ok:
                st.markdown(f"- PASS: {item.name}  ")
            else:
                st.markdown(f"- FAIL: {item.name}  ")
            st.caption(item.detail)


def maybe_auto_elevate() -> None:
    """
    Auto-attempt elevation once on launch when not admin (Windows).

    If UAC is accepted, a new elevated app is started. Current app remains usable
    in limited mode until user closes it.
    """
    if os.name != "nt":
        return

    if st.session_state.admin_mode:
        return

    if st.session_state.elevation_attempted:
        return

    st.session_state.elevation_attempted = True
    accepted = relaunch_as_admin()

    if accepted:
        st.session_state.elevation_status = "accepted"
    else:
        st.session_state.elevation_status = "declined_or_failed"


def render_elevation_status() -> None:
    status = st.session_state.elevation_status

    if status == "accepted":
        st.info(
            "Admin prompt accepted. An elevated Control Center window should open. "
            "You can continue here in limited mode or switch to the elevated window."
        )
    elif status == "declined_or_failed":
        st.warning(
            "Admin elevation was not completed. You can continue in limited mode or retry below."
        )
        if st.button("Retry Admin Elevation", use_container_width=True):
            accepted = relaunch_as_admin()
            st.session_state.elevation_status = "accepted" if accepted else "declined_or_failed"
            st.rerun()


def set_view(target: ViewState, return_to: ViewState | None = None) -> None:
    if return_to is not None:
        st.session_state.return_state = return_to
    st.session_state.view_state = target
    st.rerun()


def reset_simulation_state() -> None:
    st.session_state.sim_started = False
    st.session_state.sim_finished = False
    st.session_state.sim_success = False
    st.session_state.sim_exit_code = None
    st.session_state.sim_phase = "init"
    st.session_state.sim_logs = []
    st.session_state.sim_progress = 0


def reset_training_state() -> None:
    st.session_state.train_started = False
    st.session_state.train_finished = False
    st.session_state.train_success = False
    st.session_state.train_exit_code = None
    st.session_state.train_phase = "prep"
    st.session_state.train_logs = []
    st.session_state.train_progress = 0


def detect_attack_phase(line: str, current_phase: str) -> str:
    low = line.lower()

    if "simulation complete" in low or "training data saved" in low:
        return "finalizing"

    if "running: ssh" in low or "ssh brute force" in low or "ai honeypot" in low:
        return "ssh"

    if "running: port" in low or "port scan" in low or "portscan" in low:
        return "portscan"

    if "running: dns" in low or "dns attack simulator" in low or "[dns" in low:
        return "dns"

    if "running: icmp" in low or "icmp attack simulator" in low or "[icmp" in low:
        return "icmp"

    if "running: arp" in low or "arp spoofing" in low or "[arp" in low:
        return "arp"

    return current_phase


def detect_training_phase(line: str, current_phase: str) -> str:
    low = line.lower()

    if "[step 1]" in low or "loading" in low:
        return "load"
    if "[step 2]" in low or "extracting features" in low:
        return "features"
    if "[step 3]" in low or "generating labels" in low or "encoding labels" in low:
        return "labels"
    if "[step 5]" in low or "training random forest" in low:
        return "fit"
    if "[step 6]" in low or "evaluating" in low or "classification report" in low:
        return "evaluate"
    if "saved to" in low or "label encoder saved" in low:
        return "save"
    if "training complete" in low:
        return "done"

    return current_phase


def animation_html(phase: str) -> str:
    safe_phase = phase if phase in PHASE_LABELS else "init"
    title = PHASE_LABELS.get(safe_phase, PHASE_LABELS["init"])
    sub = PHASE_SUBTEXT.get(safe_phase, PHASE_SUBTEXT["init"])
    css_class = f"phase-{safe_phase}"

    return f"""
    <div class="phase-card {css_class}">
        <div class="phase-title">{title}</div>
        <div class="phase-row">
            <div class="phase-orb"></div>
            <div class="phase-sub">{sub}</div>
        </div>
        <div class="phase-bar"><span></span></div>
    </div>
    """


def training_animation_html(phase: str) -> str:
    safe_phase = phase if phase in TRAIN_LABELS else "prep"
    title = TRAIN_LABELS[safe_phase]
    sub = TRAIN_SUBTEXT[safe_phase]
    css_class = f"phase-{safe_phase}"

    return f"""
    <div class="phase-card {css_class}">
        <div class="phase-title">{title}</div>
        <div class="phase-row">
            <div class="phase-orb"></div>
            <div class="phase-sub">{sub}</div>
        </div>
        <div class="phase-bar"><span></span></div>
    </div>
    """


def run_simulation_job(
    phase_placeholder,
    progress_placeholder,
    status_placeholder,
    logs_placeholder,
) -> None:
    cmd = [sys.executable, "-u", str(SIM_RUNNER)]

    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"

    st.session_state.sim_started = True
    st.session_state.sim_phase = "init"
    st.session_state.sim_progress = PHASE_PROGRESS["init"]

    phase_placeholder.markdown(animation_html("init"), unsafe_allow_html=True)
    progress_placeholder.progress(st.session_state.sim_progress)
    status_placeholder.info("Starting simulation runner...")

    try:
        process = subprocess.Popen(
            cmd,
            cwd=str(ROOT_DIR),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            stdin=subprocess.PIPE,
            text=True,
            bufsize=1,
            env=env,
        )

        if process.stdin:
            # Pre-seed confirmations for runner-level and nested simulator prompts.
            process.stdin.write("yes\nyes\nyes\nyes\nyes\nyes\n")
            process.stdin.flush()

        while True:
            line = process.stdout.readline() if process.stdout else ""
            if not line and process.poll() is not None:
                break

            if not line:
                time.sleep(0.05)
                continue

            cleaned = line.rstrip()
            if cleaned:
                st.session_state.sim_logs.append(cleaned)
                st.session_state.sim_logs = st.session_state.sim_logs[-250:]

                next_phase = detect_attack_phase(cleaned, st.session_state.sim_phase)
                if next_phase != st.session_state.sim_phase:
                    st.session_state.sim_phase = next_phase
                    st.session_state.sim_progress = PHASE_PROGRESS.get(next_phase, st.session_state.sim_progress)

                phase_placeholder.markdown(
                    animation_html(st.session_state.sim_phase),
                    unsafe_allow_html=True,
                )
                progress_placeholder.progress(st.session_state.sim_progress)
                status_placeholder.info(
                    f"Current phase: {PHASE_LABELS.get(st.session_state.sim_phase, 'Running simulation')}"
                )
                logs_placeholder.code("\n".join(st.session_state.sim_logs[-35:]), language="text")

        exit_code = process.wait()
        st.session_state.sim_exit_code = exit_code
        st.session_state.sim_finished = True
        st.session_state.sim_success = exit_code == 0

        if st.session_state.sim_success:
            st.session_state.sim_phase = "done"
            st.session_state.sim_progress = PHASE_PROGRESS["done"]
            phase_placeholder.markdown(animation_html("done"), unsafe_allow_html=True)
            progress_placeholder.progress(100)
            status_placeholder.success("Simulation completed successfully.")
            st.session_state.view_state = ViewState.POST_SIMULATION
        else:
            phase_placeholder.markdown(animation_html("finalizing"), unsafe_allow_html=True)
            status_placeholder.error(
                f"Simulation failed with exit code {exit_code}."
            )

    except Exception as exc:
        st.session_state.sim_finished = True
        st.session_state.sim_success = False
        st.session_state.sim_exit_code = -1
        st.session_state.sim_logs.append(f"[control-center] simulation error: {exc}")
        logs_placeholder.code("\n".join(st.session_state.sim_logs[-35:]), language="text")
        status_placeholder.error(f"Simulation aborted: {exc}")

    st.rerun()


def run_training_job(
    phase_placeholder,
    progress_placeholder,
    status_placeholder,
    logs_placeholder,
) -> None:
    dataset_path = st.session_state.train_dataset_path or str(DATA_CSV)
    cmd = [
        sys.executable,
        "-u",
        str(TRAIN_SCRIPT),
        "--data",
        str(dataset_path),
    ]

    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"

    st.session_state.train_started = True
    st.session_state.train_phase = "prep"
    st.session_state.train_progress = TRAIN_PROGRESS["prep"]

    phase_placeholder.markdown(training_animation_html("prep"), unsafe_allow_html=True)
    progress_placeholder.progress(st.session_state.train_progress)
    status_placeholder.info(f"Training dataset: {dataset_path}")

    try:
        process = subprocess.Popen(
            cmd,
            cwd=str(ROOT_DIR),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            env=env,
        )

        while True:
            line = process.stdout.readline() if process.stdout else ""
            if not line and process.poll() is not None:
                break

            if not line:
                time.sleep(0.05)
                continue

            cleaned = line.rstrip()
            if cleaned:
                st.session_state.train_logs.append(cleaned)
                st.session_state.train_logs = st.session_state.train_logs[-250:]

                next_phase = detect_training_phase(cleaned, st.session_state.train_phase)
                if next_phase != st.session_state.train_phase:
                    st.session_state.train_phase = next_phase
                    st.session_state.train_progress = TRAIN_PROGRESS.get(next_phase, st.session_state.train_progress)

                phase_placeholder.markdown(
                    training_animation_html(st.session_state.train_phase),
                    unsafe_allow_html=True,
                )
                progress_placeholder.progress(st.session_state.train_progress)
                status_placeholder.info(
                    f"Current phase: {TRAIN_LABELS.get(st.session_state.train_phase, 'Training model')}"
                )
                logs_placeholder.code("\n".join(st.session_state.train_logs[-35:]), language="text")

        exit_code = process.wait()
        st.session_state.train_exit_code = exit_code
        st.session_state.train_finished = True
        st.session_state.train_success = exit_code == 0

        if st.session_state.train_success:
            st.session_state.train_phase = "done"
            st.session_state.train_progress = TRAIN_PROGRESS["done"]
            phase_placeholder.markdown(training_animation_html("done"), unsafe_allow_html=True)
            progress_placeholder.progress(100)
            status_placeholder.success("Model training completed successfully.")
            st.session_state.dashboard_launch_attempted = False
            st.session_state.view_state = ViewState.POST_TRAINING
        else:
            status_placeholder.error(f"Training failed with exit code {exit_code}.")

    except Exception as exc:
        st.session_state.train_finished = True
        st.session_state.train_success = False
        st.session_state.train_exit_code = -1
        st.session_state.train_logs.append(f"[control-center] training error: {exc}")
        logs_placeholder.code("\n".join(st.session_state.train_logs[-35:]), language="text")
        status_placeholder.error(f"Training aborted: {exc}")

    st.rerun()


def launch_dashboard_if_needed(force: bool = False) -> None:
    if st.session_state.dashboard_launch_attempted and not force:
        return

    st.session_state.dashboard_launch_attempted = True
    st.session_state.dashboard_launch_success = False

    cmd = [
        sys.executable,
        "-m",
        "streamlit",
        "run",
        str(DASHBOARD_SCRIPT),
        "--server.port",
        "8502",
        "--server.headless",
        "true",
    ]

    kwargs = {
        "cwd": str(ROOT_DIR),
        "stdout": subprocess.DEVNULL,
        "stderr": subprocess.DEVNULL,
    }
    if os.name == "nt" and hasattr(subprocess, "CREATE_NEW_CONSOLE"):
        kwargs["creationflags"] = subprocess.CREATE_NEW_CONSOLE

    try:
        proc = subprocess.Popen(cmd, **kwargs)
        st.session_state.dashboard_pid = proc.pid
        st.session_state.dashboard_launch_success = True
        webbrowser.open(st.session_state.dashboard_url, new=2)
    except Exception:
        st.session_state.dashboard_launch_success = False


@st.cache_data(ttl=20)
def load_csv_for_explorer(path: str) -> pd.DataFrame:
    if not Path(path).exists():
        return pd.DataFrame()

    try:
        df = pd.read_csv(path)
    except Exception:
        return pd.DataFrame()

    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")

    if "attack_type" not in df.columns:
        df["attack_type"] = "ssh"

    if "session_duration" in df.columns:
        df["session_duration"] = pd.to_numeric(df["session_duration"], errors="coerce").fillna(0.0)

    if "packet_count" in df.columns:
        df["packet_count"] = pd.to_numeric(df["packet_count"], errors="coerce").fillna(0)

    return df


def render_data_navigation_actions() -> None:
    col_back, col_home, col_train = st.columns(3)

    with col_back:
        if st.button("Back", use_container_width=True):
            set_view(st.session_state.return_state)

    with col_home:
        if st.button("Go Home", use_container_width=True):
            set_view(ViewState.HOME)

    with col_train:
        if st.button("Train on Current Data", use_container_width=True, type="primary"):
            reset_training_state()
            set_view(ViewState.RUNNING_TRAINING, return_to=ViewState.DATA_VIEW)


# -----------------------------------------------------------------------------
# View renderers (Phase 1 shell)
# -----------------------------------------------------------------------------
def render_home() -> None:
    st.subheader("Choose an action")

    col_a, col_b = st.columns(2)
    with col_a:
        st.markdown('<div class="action-kicker">Operations</div><div class="action-copy">Launch production-style workflows for simulated adversary traffic and evidence generation.</div>', unsafe_allow_html=True)
        if st.button("Launch Attack Simulation", use_container_width=True, type="primary"):
            reset_simulation_state()
            set_view(ViewState.RUNNING_SIMULATION, return_to=ViewState.HOME)
        st.caption("Run simulation orchestration with phase visuals, progress, and live operational logs.")

        if st.button("Inspect Attack Data", use_container_width=True):
            set_view(ViewState.DATA_VIEW, return_to=ViewState.HOME)
        st.caption("Explore, filter, and export session evidence using analyst-ready controls.")

    with col_b:
        st.markdown('<div class="action-kicker">Modeling</div><div class="action-copy">Train and ship your detection model with a customer-ready handoff experience to analytics.</div>', unsafe_allow_html=True)
        if st.button("Train Detection Model", use_container_width=True):
            reset_training_state()
            st.session_state.train_dataset_path = str(DATA_CSV)
            set_view(ViewState.RUNNING_TRAINING, return_to=ViewState.HOME)
        st.caption("Train detection model and transition directly to the monitoring dashboard.")

        if st.button("Open Security Dashboard", use_container_width=True):
            st.session_state.dashboard_launch_attempted = False
            set_view(ViewState.POST_TRAINING, return_to=ViewState.HOME)
        st.caption("Launch customer-facing analytics dashboard on port 8502.")


def render_running_simulation_placeholder() -> None:
    st.subheader("Simulation in progress")
    st.markdown(ANIMATION_CSS, unsafe_allow_html=True)
    st.caption("Action buttons are hidden during execution. Live status and logs are shown below.")

    phase_placeholder = st.empty()
    progress_placeholder = st.empty()
    status_placeholder = st.empty()
    logs_placeholder = st.empty()

    if not st.session_state.sim_started and not st.session_state.sim_finished:
        run_simulation_job(
            phase_placeholder,
            progress_placeholder,
            status_placeholder,
            logs_placeholder,
        )
        return

    phase_placeholder.markdown(
        animation_html(st.session_state.sim_phase),
        unsafe_allow_html=True,
    )
    progress_placeholder.progress(st.session_state.sim_progress)
    logs_placeholder.code("\n".join(st.session_state.sim_logs[-35:]), language="text")

    if st.session_state.sim_success:
        status_placeholder.success("Simulation completed successfully.")
    elif st.session_state.sim_finished:
        status_placeholder.error(
            f"Simulation failed with exit code {st.session_state.sim_exit_code}."
        )
        col_retry, col_home = st.columns(2)
        with col_retry:
            if st.button("Retry Simulation", use_container_width=True, type="primary"):
                reset_simulation_state()
                st.rerun()
        with col_home:
            if st.button("Return Home", use_container_width=True):
                set_view(ViewState.HOME)


def render_data_view_placeholder() -> None:
    st.subheader("Attack Data Explorer")
    st.caption("Filter, inspect, and export attack telemetry before model training.")

    df = load_csv_for_explorer(str(DATA_CSV))
    if df.empty:
        st.warning("No readable CSV data found. Generate simulation data first.")
        render_data_navigation_actions()
        return

    # -----------------------------------------------------------------
    # Filters
    # -----------------------------------------------------------------
    st.markdown("### Filters")
    f1, f2, f3 = st.columns(3)

    with f1:
        attack_types = sorted(df["attack_type"].dropna().astype(str).unique().tolist())
        selected_attack_types = st.multiselect(
            "Attack Type",
            options=attack_types,
            default=attack_types,
            help="Select one or more attack types.",
        )

    with f2:
        ip_query = st.text_input(
            "Source IP contains",
            value="",
            placeholder="e.g. 127.0.0.1 or 52.",
        )

    with f3:
        time_window = st.selectbox(
            "Time Window",
            options=["All Time", "Last 1 Hour", "Last 24 Hours", "Last 7 Days"],
            index=0,
        )

    g1, g2, g3 = st.columns(3)

    duration_min = float(df["session_duration"].min()) if "session_duration" in df.columns else 0.0
    duration_max = float(df["session_duration"].max()) if "session_duration" in df.columns else 1.0
    if duration_min == duration_max:
        duration_max = duration_min + 1.0

    packet_min = int(df["packet_count"].min()) if "packet_count" in df.columns else 0
    packet_max = int(df["packet_count"].max()) if "packet_count" in df.columns else 1
    if packet_min == packet_max:
        packet_max = packet_min + 1

    with g1:
        duration_range = st.slider(
            "Session Duration (seconds)",
            min_value=float(duration_min),
            max_value=float(duration_max),
            value=(float(duration_min), float(duration_max)),
        )

    with g2:
        packet_range = st.slider(
            "Packet Count",
            min_value=int(packet_min),
            max_value=int(packet_max),
            value=(int(packet_min), int(packet_max)),
        )

    with g3:
        global_search = st.text_input(
            "Global Search",
            value="",
            placeholder="Find text across visible columns",
        )

    filtered = df.copy()

    if selected_attack_types:
        filtered = filtered[filtered["attack_type"].astype(str).isin(selected_attack_types)]

    if ip_query.strip() and "ip_address" in filtered.columns:
        filtered = filtered[
            filtered["ip_address"].astype(str).str.contains(ip_query.strip(), case=False, na=False)
        ]

    if "session_duration" in filtered.columns:
        filtered = filtered[
            (filtered["session_duration"] >= duration_range[0])
            & (filtered["session_duration"] <= duration_range[1])
        ]

    if "packet_count" in filtered.columns:
        filtered = filtered[
            (filtered["packet_count"] >= packet_range[0])
            & (filtered["packet_count"] <= packet_range[1])
        ]

    if time_window != "All Time" and "timestamp" in filtered.columns:
        now = pd.Timestamp.now()
        if time_window == "Last 1 Hour":
            cutoff = now - pd.Timedelta(hours=1)
        elif time_window == "Last 24 Hours":
            cutoff = now - pd.Timedelta(hours=24)
        else:
            cutoff = now - pd.Timedelta(days=7)
        filtered = filtered[filtered["timestamp"] >= cutoff]

    # Column selection for display and search scope
    core_columns = [
        col
        for col in [
            "timestamp",
            "ip_address",
            "attack_type",
            "session_duration",
            "packet_count",
            "login_attempts",
            "commands_sent",
            "scan_type",
            "dns_query_type",
            "icmp_type",
        ]
        if col in filtered.columns
    ]
    all_columns = filtered.columns.tolist()

    selected_columns = st.multiselect(
        "Visible Columns",
        options=all_columns,
        default=core_columns if core_columns else all_columns,
        help="Choose which columns to display and search.",
    )
    if not selected_columns:
        selected_columns = all_columns

    display_df = filtered[selected_columns].copy()

    if global_search.strip():
        needle = global_search.strip().lower()
        row_match = display_df.apply(
            lambda row: any(needle in str(v).lower() for v in row.values),
            axis=1,
        )
        display_df = display_df[row_match]

    # -----------------------------------------------------------------
    # Quick stats
    # -----------------------------------------------------------------
    s1, s2, s3, s4 = st.columns(4)
    with s1:
        st.metric("Rows (Filtered)", f"{len(display_df):,}")
    with s2:
        st.metric("Rows (Total)", f"{len(df):,}")
    with s3:
        unique_ips = display_df["ip_address"].nunique() if "ip_address" in display_df.columns else 0
        st.metric("Unique IPs", f"{unique_ips:,}")
    with s4:
        unique_types = display_df["attack_type"].nunique() if "attack_type" in display_df.columns else 0
        st.metric("Attack Types", f"{unique_types:,}")

    # -----------------------------------------------------------------
    # Table and export
    # -----------------------------------------------------------------
    st.markdown("### Data Table")
    st.dataframe(display_df, use_container_width=True, hide_index=True)

    csv_bytes = display_df.to_csv(index=False).encode("utf-8")
    st.download_button(
        label="Export Filtered CSV",
        data=csv_bytes,
        file_name="attack_logs_filtered.csv",
        mime="text/csv",
        use_container_width=True,
    )

    # Store full filtered dataset for upcoming training phase.
    temp_train_path = ROOT_DIR / "data" / "attack_logs_filtered_ui.csv"
    filtered.to_csv(temp_train_path, index=False)
    st.session_state.train_dataset_path = str(temp_train_path)

    st.markdown("### Actions")
    render_data_navigation_actions()


def render_running_training_placeholder() -> None:
    st.subheader("Model training in progress")
    st.markdown(ANIMATION_CSS, unsafe_allow_html=True)
    st.caption("Training runs with live status and logs. Dashboard opens automatically on success.")

    phase_placeholder = st.empty()
    progress_placeholder = st.empty()
    status_placeholder = st.empty()
    logs_placeholder = st.empty()

    if not st.session_state.train_started and not st.session_state.train_finished:
        run_training_job(
            phase_placeholder,
            progress_placeholder,
            status_placeholder,
            logs_placeholder,
        )
        return

    phase_placeholder.markdown(
        training_animation_html(st.session_state.train_phase),
        unsafe_allow_html=True,
    )
    progress_placeholder.progress(st.session_state.train_progress)
    logs_placeholder.code("\n".join(st.session_state.train_logs[-35:]), language="text")

    if st.session_state.train_success:
        status_placeholder.success("Training completed successfully.")
    elif st.session_state.train_finished:
        status_placeholder.error(
            f"Training failed with exit code {st.session_state.train_exit_code}."
        )
        col_retry, col_home = st.columns(2)
        with col_retry:
            if st.button("Retry Training", use_container_width=True, type="primary"):
                reset_training_state()
                st.rerun()
        with col_home:
            if st.button("Return Home", use_container_width=True):
                set_view(ViewState.HOME)


def render_dashboard_placeholder() -> None:
    st.subheader("Dashboard handoff")
    st.caption("Opening the operational dashboard on port 8502.")

    if not st.session_state.dashboard_launch_attempted:
        launch_dashboard_if_needed()

    if st.session_state.dashboard_launch_success:
        st.success("Dashboard launched. A browser tab should open automatically.")
        st.markdown(f"Open manually: {st.session_state.dashboard_url}")
        if st.session_state.dashboard_pid:
            st.caption(f"Dashboard process id: {st.session_state.dashboard_pid}")
    else:
        st.warning("Dashboard launch could not be confirmed. You can retry below.")

    c1, c2, c3 = st.columns(3)
    with c1:
        if st.button("Open Dashboard in Browser", use_container_width=True, type="primary"):
            webbrowser.open(st.session_state.dashboard_url, new=2)
    with c2:
        if st.button("Relaunch Dashboard", use_container_width=True):
            launch_dashboard_if_needed(force=True)
            st.rerun()
    with c3:
        if st.button("Go Home", use_container_width=True):
            set_view(ViewState.HOME)


def render_post_simulation() -> None:
    st.subheader("Simulation finished")
    if st.session_state.sim_success:
        st.success("Attack simulation completed. Choose your next step.")
    else:
        st.warning("Simulation ended with issues. You can still continue with available actions.")

    c1, c2, c3 = st.columns(3)
    with c1:
        if st.button("Inspect Attack Data", use_container_width=True, type="primary"):
            set_view(ViewState.DATA_VIEW, return_to=ViewState.POST_SIMULATION)
    with c2:
        if st.button("Train Detection Model", use_container_width=True):
            reset_training_state()
            st.session_state.train_dataset_path = str(DATA_CSV)
            set_view(ViewState.RUNNING_TRAINING, return_to=ViewState.POST_SIMULATION)
    with c3:
        if st.button("Open Security Dashboard", use_container_width=True):
            st.session_state.dashboard_launch_attempted = False
            set_view(ViewState.POST_TRAINING, return_to=ViewState.POST_SIMULATION)


# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------
def main() -> None:
    st.set_page_config(
        page_title="Security Control Center",
        page_icon="SCC",
        layout="wide",
        initial_sidebar_state="expanded",
    )

    init_state()
    maybe_auto_elevate()

    render_header()
    render_capability_banner()
    render_elevation_status()
    render_startup_checks()

    st.divider()

    view = st.session_state.view_state

    if view == ViewState.HOME:
        render_home()
    elif view == ViewState.RUNNING_SIMULATION:
        render_running_simulation_placeholder()
    elif view == ViewState.POST_SIMULATION:
        render_post_simulation()
    elif view == ViewState.DATA_VIEW:
        render_data_view_placeholder()
    elif view == ViewState.RUNNING_TRAINING:
        render_running_training_placeholder()
    elif view == ViewState.POST_TRAINING:
        render_dashboard_placeholder()
    else:
        render_home()


if __name__ == "__main__":
    main()
