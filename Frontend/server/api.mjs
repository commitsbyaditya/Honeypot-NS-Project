import http from "node:http";
import { spawn } from "node:child_process";
import { createInterface } from "node:readline";
import path from "node:path";
import { fileURLToPath } from "node:url";
import fs from "node:fs";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const frontendRoot = path.resolve(__dirname, "..");
const repoRoot = path.resolve(frontendRoot, "..");
const pythonExe = fs.existsSync(path.join(repoRoot, ".venv", "Scripts", "python.exe"))
  ? path.join(repoRoot, ".venv", "Scripts", "python.exe")
  : "python";
const bridgeScript = path.join(frontendRoot, "server", "project_bridge.py");

const PORT = Number(process.env.FRONTEND_API_PORT || 8787);
const MAX_LOG_LINES = 2000;

const jobs = new Map();
const jobProcesses = new Map();

function json(res, statusCode, payload) {
  res.writeHead(statusCode, {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Content-Type",
    "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
  });
  res.end(JSON.stringify(payload));
}

function addLog(job, line) {
  job.logs.push(line);
  if (job.logs.length > MAX_LOG_LINES) {
    job.logs.splice(0, job.logs.length - MAX_LOG_LINES);
  }
}

function cleanupSimulationProcesses() {
  if (process.platform === "win32") {
    return new Promise((resolve) => {
      const script = [
        "$procs = Get-CimInstance Win32_Process -Filter \"Name='python.exe'\" | Where-Object { $_.CommandLine -match 'run_all_simulators\\.py|attack_simulator(_arp|_dns|_icmp|_portscan)?\\.py' }",
        "if ($procs) { $procs | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }; ($procs | Measure-Object).Count } else { 0 }",
      ].join("; ");
      const child = spawn("powershell", ["-NoProfile", "-Command", script], { windowsHide: true });
      let stdout = "";

      child.stdout.on("data", (chunk) => {
        stdout += chunk.toString();
      });

      child.on("error", () => resolve(0));
      child.on("close", () => {
        const count = Number.parseInt(stdout.trim(), 10);
        resolve(Number.isNaN(count) ? 0 : count);
      });
    });
  }

  return new Promise((resolve) => {
    const child = spawn("sh", ["-lc", "pkill -f 'run_all_simulators.py|attack_simulator(_arp|_dns|_icmp|_portscan)?.py' >/dev/null 2>&1; echo $?"], {
      windowsHide: true,
    });
    child.on("error", () => resolve(0));
    child.on("close", () => resolve(0));
  });
}

function killProcessTree(pid) {
  if (!pid) {
    return Promise.resolve(false);
  }

  if (process.platform === "win32") {
    return new Promise((resolve) => {
      const child = spawn("taskkill", ["/PID", String(pid), "/T", "/F"], { windowsHide: true });
      child.on("error", () => resolve(false));
      child.on("close", (code) => resolve(code === 0));
    });
  }

  return new Promise((resolve) => {
    const child = spawn("sh", ["-lc", `kill -TERM -${pid} >/dev/null 2>&1 || kill -TERM ${pid} >/dev/null 2>&1`], {
      windowsHide: true,
    });
    child.on("error", () => resolve(false));
    child.on("close", (code) => resolve(code === 0));
  });
}

async function stopJob(id, reason = "Stopped by user") {
  const job = jobs.get(id);
  if (!job) {
    return { found: false, stopped: false, cleaned: 0 };
  }

  if (job.type === "simulation") {
    const summary = await stopAllSimulationRuns(reason);
    return {
      found: true,
      stopped: summary.stopped || summary.stoppedJobs > 0 || summary.cleaned > 0,
      cleaned: summary.cleaned,
    };
  }

  let stopped = false;
  const child = jobProcesses.get(id);
  if (child?.pid && job.status === "running") {
    stopped = await killProcessTree(child.pid);
  }

  job.stopRequested = true;
  if (job.status === "running") {
    job.status = "failed";
    job.exitCode = -1;
    job.endedAt = new Date().toISOString();
    addLog(job, `[SYSTEM] ${reason}`);
  }

  let cleaned = 0;
  if (job.type === "simulation") {
    cleaned = await cleanupSimulationProcesses();
    if (cleaned > 0) {
      addLog(job, `[SYSTEM] Stopped ${cleaned} simulator process(es).`);
    }
  }

  return { found: true, stopped, cleaned };
}

async function stopAllSimulationRuns(reason = "Simulation stopped by user") {
  const simulationJobs = [...jobs.values()].filter((job) => job.type === "simulation" && job.status === "running");

  let stopped = false;
  for (const job of simulationJobs) {
    const child = jobProcesses.get(job.id);
    if (child?.pid) {
      const killed = await killProcessTree(child.pid);
      stopped = stopped || killed;
    }

    job.stopRequested = true;
    job.status = "failed";
    job.exitCode = -1;
    job.endedAt = new Date().toISOString();
    addLog(job, `[SYSTEM] ${reason}`);
  }

  const cleaned = await cleanupSimulationProcesses();
  if (cleaned > 0) {
    for (const job of simulationJobs) {
      addLog(job, `[SYSTEM] Stopped ${cleaned} simulator process(es).`);
    }
  }

  return {
    stoppedJobs: simulationJobs.length,
    stopped,
    cleaned,
  };
}

function createJob(type, command, args, opts = {}) {
  const id = `${type}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;

  const childEnv = { ...process.env };
  if (command === pythonExe) {
    // Force immediate stdout/stderr flushing so UI terminal shows live logs.
    childEnv.PYTHONUNBUFFERED = "1";
  }

  const child = spawn(command, args, {
    cwd: repoRoot,
    windowsHide: true,
    env: childEnv,
  });

  const job = {
    id,
    type,
    status: "running",
    startedAt: new Date().toISOString(),
    endedAt: null,
    exitCode: null,
    logs: [],
    pid: child.pid ?? null,
    stopRequested: false,
  };

  jobs.set(id, job);
  jobProcesses.set(id, child);
  addLog(job, `[SYSTEM] Started ${type} job (pid=${job.pid ?? "n/a"})`);

  const stdoutRl = createInterface({ input: child.stdout });
  const stderrRl = createInterface({ input: child.stderr });

  stdoutRl.on("line", (line) => addLog(job, line));
  stderrRl.on("line", (line) => addLog(job, `[ERR] ${line}`));

  child.on("error", (err) => {
    addLog(job, `[ERR] ${err.message}`);
    job.status = "failed";
    job.endedAt = new Date().toISOString();
  });

  child.on("close", (code) => {
    if (!job.stopRequested) {
      job.exitCode = code;
      job.status = code === 0 ? "completed" : "failed";
      job.endedAt = new Date().toISOString();
    } else if (!job.endedAt) {
      job.exitCode = code;
      job.status = "failed";
      job.endedAt = new Date().toISOString();
    }

    jobProcesses.delete(id);
    if (type === "simulation") {
      void cleanupSimulationProcesses();
    }
  });

  if (opts.autoYes) {
    setTimeout(() => {
      try {
        child.stdin.write("yes\n");
      } catch {
        // no-op
      }
    }, 400);
  }

  return job;
}

function runBridge(command, query = {}) {
  const args = [
    bridgeScript,
    command,
    "--repo-root",
    repoRoot,
    "--search",
    query.search || "",
    "--attack-type",
    query.attackType || "all",
    "--sort-key",
    query.sortKey || "timestamp",
    "--sort-order",
    query.sortOrder || "desc",
    "--limit",
    String(Number(query.limit || 200)),
  ];

  return new Promise((resolve, reject) => {
    const child = spawn(pythonExe, args, { cwd: repoRoot, windowsHide: true });
    let stdout = "";
    let stderr = "";

    child.stdout.on("data", (chunk) => {
      stdout += chunk.toString();
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk.toString();
    });
    child.on("error", reject);
    child.on("close", (code) => {
      if (code !== 0) {
        reject(new Error(stderr || `Bridge exited with code ${code}`));
        return;
      }
      try {
        resolve(JSON.parse(stdout.trim() || "{}"));
      } catch (err) {
        reject(err);
      }
    });
  });
}

function parseBody(req) {
  return new Promise((resolve, reject) => {
    let raw = "";
    req.on("data", (chunk) => {
      raw += chunk.toString();
    });
    req.on("end", () => {
      if (!raw) {
        resolve({});
        return;
      }
      try {
        resolve(JSON.parse(raw));
      } catch (err) {
        reject(err);
      }
    });
    req.on("error", reject);
  });
}

function isLocalPortListening(port) {
  if (process.platform === "win32") {
    return new Promise((resolve) => {
      const script = `if (Get-NetTCPConnection -State Listen -LocalPort ${port} -ErrorAction SilentlyContinue) { 'true' } else { 'false' }`;
      const child = spawn("powershell", ["-NoProfile", "-Command", script], { windowsHide: true });
      let stdout = "";

      child.stdout.on("data", (chunk) => {
        stdout += chunk.toString();
      });

      child.on("error", () => resolve(false));
      child.on("close", () => {
        resolve(stdout.trim().toLowerCase() === "true");
      });
    });
  }

  return new Promise((resolve) => {
    const child = spawn("sh", ["-lc", `netstat -ltn 2>/dev/null | grep -q ':${port} ' && echo true || echo false`], {
      windowsHide: true,
    });
    let stdout = "";

    child.stdout.on("data", (chunk) => {
      stdout += chunk.toString();
    });

    child.on("error", () => resolve(false));
    child.on("close", () => {
      resolve(stdout.trim().toLowerCase() === "true");
    });
  });
}

function checkHoneypotManagerProcess() {
  if (process.platform === "win32") {
    return new Promise((resolve) => {
      const script = "$p = Get-CimInstance Win32_Process -Filter \"Name='python.exe'\" | Where-Object { $_.CommandLine -match 'honeypot_manager\\.py' }; if ($p) { 'true' } else { 'false' }";
      const child = spawn("powershell", ["-NoProfile", "-Command", script], { windowsHide: true });
      let stdout = "";

      child.stdout.on("data", (chunk) => {
        stdout += chunk.toString();
      });

      child.on("error", () => resolve(false));
      child.on("close", (code) => {
        if (code !== 0) {
          resolve(false);
          return;
        }
        resolve(stdout.trim().toLowerCase() === "true");
      });
    });
  }

  return new Promise((resolve) => {
    const child = spawn("sh", ["-lc", "pgrep -f honeypot_manager.py >/dev/null && echo true || echo false"], {
      windowsHide: true,
    });
    let stdout = "";

    child.stdout.on("data", (chunk) => {
      stdout += chunk.toString();
    });

    child.on("error", () => resolve(false));
    child.on("close", () => {
      resolve(stdout.trim().toLowerCase() === "true");
    });
  });
}

async function getHoneypotStatus() {
  const [sshPortOpen, dnsPortOpen, managerProcessDetected] = await Promise.all([
    isLocalPortListening(2222),
    isLocalPortListening(53),
    checkHoneypotManagerProcess(),
  ]);

  const honeypotActive = managerProcessDetected && sshPortOpen;
  return {
    honeypotActive,
    managerProcessDetected,
    sshPortOpen,
    dnsPortOpen,
    attackSimulationAllowed: honeypotActive,
    honeypotHint: honeypotActive
      ? "Honeypot manager is active. Attack simulation is enabled."
      : "Start honeypot_manager.py first, then retry simulation.",
  };
}

function buildAdminStatus(isAdmin, honeypotStatus) {
  const isWindows = process.platform === "win32";
  const derivedFromRuntime = Boolean(
    honeypotStatus?.managerProcessDetected && honeypotStatus?.dnsPortOpen,
  );
  const effectiveAdmin = isAdmin || derivedFromRuntime;

  const hint = effectiveAdmin
    ? "Admin/capability checks are satisfied for current runtime."
    : isWindows
      ? "Run VS Code (or the API/honeypot terminals) as Administrator for full detector coverage."
      : "Run the backend with sudo/root for full detector coverage.";

  return {
    isAdmin: effectiveAdmin,
    apiProcessIsAdmin: isAdmin,
    adminDerivedFromRuntime: derivedFromRuntime,
    platform: process.platform,
    canRequestAdmin: isWindows,
    adminHint: hint,
  };
}

function checkAdminPrivileges() {
  if (process.platform === "win32") {
    return new Promise((resolve) => {
      const psCheck = "[bool]([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)";
      const child = spawn("powershell", ["-NoProfile", "-Command", psCheck], { windowsHide: true });
      let stdout = "";

      child.stdout.on("data", (chunk) => {
        stdout += chunk.toString();
      });

      child.on("error", () => resolve(false));
      child.on("close", (code) => {
        if (code !== 0) {
          resolve(false);
          return;
        }
        resolve(stdout.trim().toLowerCase() === "true");
      });
    });
  }

  if (typeof process.getuid === "function") {
    return Promise.resolve(process.getuid() === 0);
  }

  return Promise.resolve(false);
}

function requestAdminShell() {
  if (process.platform !== "win32") {
    return Promise.resolve({
      launched: false,
      message: "Automated elevation is available on Windows only. Run backend with sudo/root.",
    });
  }

  return new Promise((resolve) => {
    const psScript = "Start-Process -FilePath PowerShell -Verb RunAs -WindowStyle Normal";
    const child = spawn("powershell", ["-NoProfile", "-Command", psScript], {
      windowsHide: false,
    });

    let stderr = "";
    child.stderr.on("data", (chunk) => {
      stderr += chunk.toString();
    });

    child.on("error", (err) => {
      resolve({
        launched: false,
        message: `Unable to request admin prompt: ${err.message}`,
      });
    });

    child.on("close", (code) => {
      if (code === 0) {
        resolve({
          launched: true,
          message: "UAC prompt requested. Approve it, then run commands in the new elevated PowerShell window.",
        });
        return;
      }

      resolve({
        launched: false,
        message: `Admin prompt was not started (code ${code}). ${stderr.trim() || "Try opening PowerShell as Administrator manually."}`,
      });
    });
  });
}

const server = http.createServer(async (req, res) => {
  if (!req.url || !req.method) {
    json(res, 400, { error: "Invalid request" });
    return;
  }

  if (req.method === "OPTIONS") {
    json(res, 200, { ok: true });
    return;
  }

  const url = new URL(req.url, `http://${req.headers.host}`);

  try {
    if (req.method === "GET" && url.pathname === "/api/health") {
      const payload = await runBridge("health");
      const isAdmin = await checkAdminPrivileges();
      const honeypotStatus = await getHoneypotStatus();
      json(res, 200, { ...payload, ...buildAdminStatus(isAdmin, honeypotStatus), ...honeypotStatus });
      return;
    }

    if (req.method === "GET" && url.pathname === "/api/system/admin-status") {
      const isAdmin = await checkAdminPrivileges();
      const honeypotStatus = await getHoneypotStatus();
      json(res, 200, buildAdminStatus(isAdmin, honeypotStatus));
      return;
    }

    if (req.method === "POST" && url.pathname === "/api/system/request-admin") {
      const result = await requestAdminShell();
      json(res, 200, result);
      return;
    }

    if (req.method === "GET" && url.pathname === "/api/system/honeypot-status") {
      const honeypotStatus = await getHoneypotStatus();
      json(res, 200, honeypotStatus);
      return;
    }

    if (req.method === "GET" && url.pathname === "/api/data/sessions") {
      const payload = await runBridge("sessions", {
        search: url.searchParams.get("search") || "",
        attackType: url.searchParams.get("attackType") || "all",
        sortKey: url.searchParams.get("sortKey") || "timestamp",
        sortOrder: url.searchParams.get("sortOrder") || "desc",
        limit: Number(url.searchParams.get("limit") || "200"),
      });
      json(res, 200, payload);
      return;
    }

    if (req.method === "GET" && url.pathname === "/api/data/stats") {
      const payload = await runBridge("stats");
      json(res, 200, payload);
      return;
    }

    if (req.method === "POST" && url.pathname === "/api/simulation/start") {
      const honeypotStatus = await getHoneypotStatus();
      if (!honeypotStatus.attackSimulationAllowed) {
        json(res, 409, {
          error: "Honeypot is not active. Start honeypot_manager.py before launching attack simulation.",
          ...honeypotStatus,
        });
        return;
      }

      const body = await parseBody(req);
      const mode = String(body.mode || "quick").toLowerCase();
      const attackType = String(body.attackType || "all").toLowerCase();
      const selectableAttackTypes = ["all", "ssh", "portscan", "dns", "icmp", "arp"];

      if (!selectableAttackTypes.includes(attackType)) {
        json(res, 400, { error: "Invalid attackType. Use one of: all, ssh, portscan, dns, icmp, arp." });
        return;
      }

      const args = [path.join(repoRoot, "run_all_simulators.py")];
      if (mode === "intensive") {
        args.push("--intensive");
      } else if (mode === "normal") {
        // default behavior
      } else {
        args.push("--quick");
      }

      if (attackType !== "all") {
        const skipTypes = ["ssh", "portscan", "dns", "icmp", "arp"].filter((item) => item !== attackType);
        args.push("--skip", ...skipTypes);
      }

      args.push("--auto");

      const job = createJob("simulation", pythonExe, args);
      json(res, 200, { jobId: job.id, status: job.status });
      return;
    }

    if (req.method === "POST" && url.pathname === "/api/simulation/stop-all") {
      const result = await stopAllSimulationRuns("Simulation stopped from frontend navigation.");
      json(res, 200, {
        ok: true,
        stoppedJobs: result.stoppedJobs,
        stopped: result.stopped,
        cleaned: result.cleaned,
      });
      return;
    }

    if (req.method === "POST" && url.pathname === "/api/training/start") {
      const body = await parseBody(req);
      const args = [path.join(repoRoot, "ml", "train_model_multi.py")];
      if (body?.dataPath) {
        args.push("--data", String(body.dataPath));
      }

      const job = createJob("training", pythonExe, args);
      json(res, 200, { jobId: job.id, status: job.status });
      return;
    }

    if (req.method === "POST" && url.pathname === "/api/dashboard/start") {
      const port = Number(process.env.FRONTEND_DASHBOARD_PORT || 8502);
      const args = [
        "-m",
        "streamlit",
        "run",
        path.join(repoRoot, "dashboard", "dashboard_multi.py"),
        "--server.headless",
        "true",
        "--server.port",
        String(port),
      ];

      const job = createJob("dashboard", pythonExe, args);
      json(res, 200, { jobId: job.id, url: `http://localhost:${port}` });
      return;
    }

    if (req.method === "POST" && /^\/api\/jobs\/[^/]+\/stop$/.test(url.pathname)) {
      const id = url.pathname.split("/")[3];
      const result = await stopJob(id, "Simulation aborted from frontend.");
      if (!result.found) {
        json(res, 404, { error: "Job not found" });
        return;
      }
      const job = jobs.get(id);
      json(res, 200, {
        ok: true,
        stopped: result.stopped,
        cleaned: result.cleaned,
        status: job?.status || "failed",
      });
      return;
    }

    if (req.method === "GET" && url.pathname.startsWith("/api/jobs/")) {
      const id = url.pathname.split("/").pop();
      const job = jobs.get(id);
      if (!job) {
        json(res, 404, { error: "Job not found" });
        return;
      }
      const { stopRequested: _unusedStopRequested, ...safeJob } = job;
      json(res, 200, safeJob);
      return;
    }

    json(res, 404, { error: "Not found" });
  } catch (err) {
    json(res, 500, { error: err.message || "Internal server error" });
  }
});

server.listen(PORT, () => {
  // eslint-disable-next-line no-console
  console.log(`[frontend-api] listening on http://localhost:${PORT}`);
  // eslint-disable-next-line no-console
  console.log(`[frontend-api] repo root: ${repoRoot}`);
});
