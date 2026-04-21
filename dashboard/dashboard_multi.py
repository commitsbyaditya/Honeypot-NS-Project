"""
Multi-Attack Security Dashboard
================================

Enhanced dashboard supporting all 5 attack types with:
  - Attack type filtering
  - Type-specific metrics
  - Unified timeline view
  - Cross-attack correlation
  - Enhanced visualizations

Usage:
    streamlit run dashboard/dashboard_multi.py
"""

import os
import sys
import importlib.util
import pandas as pd
import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta

# ═══════════════════════════════════════════════════════════════════════════
# IMPORT PROJECT MODULES
# ═══════════════════════════════════════════════════════════════════════════
_PARENT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, _PARENT_DIR)

# Load attack_logger
_logger_spec = importlib.util.spec_from_file_location(
    "attack_logger",
    os.path.join(_PARENT_DIR, "logging", "attack_logger.py"),
)
_attack_logger_mod = importlib.util.module_from_spec(_logger_spec)
_logger_spec.loader.exec_module(_attack_logger_mod)
LOG_COLUMNS = _attack_logger_mod.LOG_COLUMNS

# Load multi-attack classifier
from ml.attack_classifier_multi import predict_attack, get_severity, get_attack_category

# ═══════════════════════════════════════════════════════════════════════════
# PATH CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════
_CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_PATH = os.path.join(_CURRENT_DIR, "..", "data", "attack_logs.csv")

# ═══════════════════════════════════════════════════════════════════════════
# PAGE CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════
st.set_page_config(
    page_title="Network Security Monitoring Platform",
    page_icon="■",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ═══════════════════════════════════════════════════════════════════════════
# PROFESSIONAL DARK THEME
# ═══════════════════════════════════════════════════════════════════════════
_PROFESSIONAL_CSS = """
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap');
    
    /* Global Styles */
    .stApp { 
        background-color: #0f1419; 
        color: #e6edf3;
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    }
    
    /* Sidebar */
    section[data-testid="stSidebar"] { 
        background-color: #0d1117; 
        border-right: 1px solid #21262d;
    }
    section[data-testid="stSidebar"] .css-1d391kg {
        padding-top: 2rem;
    }
    
    /* Typography */
    h1, h2, h3, h4 { 
        color: #f0f6fc !important; 
        font-family: 'Inter', sans-serif !important;
        font-weight: 600 !important;
        letter-spacing: -0.02em;
    }
    h1 { font-size: 2.25rem !important; margin-bottom: 0.5rem !important; }
    h2 { font-size: 1.5rem !important; margin-top: 2rem !important; margin-bottom: 1rem !important; }
    h3 { font-size: 1.125rem !important; margin-top: 1.5rem !important; }
    
    /* Metrics */
    [data-testid="stMetric"] { 
        background: linear-gradient(135deg, #161b22 0%, #0d1117 100%);
        border: 1px solid #30363d; 
        border-radius: 12px; 
        padding: 1.5rem;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.3);
        transition: all 0.3s ease;
    }
    [data-testid="stMetric"]:hover {
        border-color: #58a6ff;
        box-shadow: 0 6px 12px rgba(88, 166, 255, 0.15);
    }
    [data-testid="stMetricValue"] { 
        color: #58a6ff !important; 
        font-family: 'JetBrains Mono', monospace !important;
        font-size: 2rem !important;
        font-weight: 600 !important;
    }
    [data-testid="stMetricLabel"] { 
        color: #8b949e !important;
        font-size: 0.875rem !important;
        font-weight: 500 !important;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }
    [data-testid="stMetricDelta"] {
        font-family: 'JetBrains Mono', monospace !important;
    }
    
    /* Tables */
    .stDataFrame { 
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.875rem;
    }
    thead tr th { 
        background-color: #161b22 !important; 
        color: #f0f6fc !important;
        font-weight: 600 !important;
        text-transform: uppercase;
        font-size: 0.75rem !important;
        letter-spacing: 0.05em;
        padding: 1rem !important;
    }
    tbody tr { 
        background-color: #0d1117 !important; 
        color: #e6edf3 !important;
        border-bottom: 1px solid #21262d !important;
    }
    tbody tr:hover { 
        background-color: #161b22 !important;
    }
    
    /* Banner */
    .professional-banner { 
        background: linear-gradient(135deg, #161b22 0%, #0d1117 100%);
        border-left: 4px solid #58a6ff;
        border-radius: 8px;
        padding: 1.25rem 1.5rem;
        margin-bottom: 2rem;
        font-family: 'Inter', sans-serif;
        color: #f0f6fc;
        font-size: 0.9375rem;
        font-weight: 500;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.2);
    }
    
    /* Alert Badges */
    .alert-badge {
        display: inline-block;
        padding: 0.25rem 0.75rem;
        border-radius: 12px;
        font-size: 0.75rem;
        font-weight: 600;
        font-family: 'Inter', sans-serif;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }
    .severity-critical { 
        background-color: rgba(248, 81, 73, 0.15);
        color: #f85149 !important;
        border: 1px solid rgba(248, 81, 73, 0.3);
    }
    .severity-high { 
        background-color: rgba(255, 136, 0, 0.15);
        color: #ff8800 !important;
        border: 1px solid rgba(255, 136, 0, 0.3);
    }
    .severity-medium { 
        background-color: rgba(212, 167, 44, 0.15);
        color: #d4a72c !important;
        border: 1px solid rgba(212, 167, 44, 0.3);
    }
    .severity-low { 
        background-color: rgba(46, 160, 67, 0.15);
        color: #2ea043 !important;
        border: 1px solid rgba(46, 160, 67, 0.3);
    }
    
    /* Buttons */
    .stButton button {
        background: linear-gradient(135deg, #238636 0%, #2ea043 100%);
        color: white;
        border: none;
        border-radius: 6px;
        font-weight: 500;
        font-family: 'Inter', sans-serif;
        padding: 0.5rem 1rem;
        transition: all 0.2s ease;
    }
    .stButton button:hover {
        background: linear-gradient(135deg, #2ea043 0%, #238636 100%);
        box-shadow: 0 4px 12px rgba(46, 160, 67, 0.3);
    }
    
    /* Select Boxes */
    .stSelectbox > div > div {
        background-color: #161b22;
        border: 1px solid #30363d;
        border-radius: 6px;
        color: #e6edf3;
    }
    
    /* Charts */
    .js-plotly-plot {
        border-radius: 8px;
        overflow: hidden;
    }
</style>
"""
st.markdown(_PROFESSIONAL_CSS, unsafe_allow_html=True)

# ═══════════════════════════════════════════════════════════════════════════
# DATA LOADING
# ═══════════════════════════════════════════════════════════════════════════
@st.cache_data(ttl=30)
def load_attack_data() -> pd.DataFrame:
    """Load attack_logs.csv with ML predictions."""
    try:
        if not os.path.exists(DATA_PATH):
            return pd.DataFrame()
        
        # Use unified data loader that handles mixed CSV formats
        from ml.data_loader import load_mixed_csv
        df = load_mixed_csv(DATA_PATH, verbose=False)
        
        if df.empty:
            return pd.DataFrame()
        
        # Parse timestamps
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
        
        # If no attack_type column, add predictions
        if "attack_type" not in df.columns or df["attack_type"].isna().all():
            df["attack_type"] = "ssh"  # Default to SSH for legacy data
        
        # Add ML predictions for classification
        def get_prediction(row):
            attack_type = str(row.get("attack_type", "ssh"))
            try:
                return predict_attack(
                    attack_type=attack_type,
                    session_duration=float(row.get("session_duration", 0) or 0),
                    packet_count=int(row.get("packet_count", 0) or 0),
                    login_attempts=int(row.get("login_attempts", 0) or 0),
                    successful_login=int(row.get("successful_login", 0) or 0),
                    commands_sent=int(row.get("commands_sent", 0) or 0),
                    command_types=int(row.get("command_types", 0) or 0),
                    scan_speed=float(row.get("scan_speed", 0) or 0),
                    stealth_detected=int(row.get("stealth_detected", 0) or 0),
                    syn_count=int(row.get("syn_count", 0) or 0),
                    query_rate=float(row.get("query_rate", 0) or 0),
                    tunneling_detected=int(row.get("tunneling_detected", 0) or 0),
                    amplification_detected=int(row.get("amplification_detected", 0) or 0),
                    arp_reply_rate=float(row.get("arp_reply_rate", 0) or 0),
                    gratuitous_arp=int(row.get("gratuitous_arp", 0) or 0),
                    ip_conflict=int(row.get("ip_conflict", 0) or 0),
                    mac_conflict=int(row.get("mac_conflict", 0) or 0),
                    icmp_rate=float(row.get("icmp_rate", 0) or 0),
                    flood_detected=int(row.get("flood_detected", 0) or 0),
                    oversized_detected=int(row.get("oversized_detected", 0) or 0),
                    packet_size=int(row.get("packet_size", 0) or 0),
                )
            except:
                return "Unknown"
        
        df["predicted_label"] = df.apply(get_prediction, axis=1)
        df["severity"] = df["predicted_label"].apply(get_severity)
        df["category"] = df["predicted_label"].apply(get_attack_category)
        
        return df
    except Exception as e:
        st.error(f"Error loading data: {e}")
        return pd.DataFrame()

# ═══════════════════════════════════════════════════════════════════════════
# SIDEBAR FILTERS
# ═══════════════════════════════════════════════════════════════════════════
def render_sidebar(df: pd.DataFrame):
    """Render sidebar with attack type filters."""
    st.sidebar.markdown("## FILTERS")
    st.sidebar.markdown("---")
    
    # Attack type filter
    st.sidebar.markdown("### Attack Type")
    attack_types = ["All"] + sorted(df["attack_type"].dropna().unique().tolist()) if not df.empty else ["All"]
    selected_type = st.sidebar.selectbox("Select attack type", attack_types, label_visibility="collapsed")
    
    # Severity filter
    st.sidebar.markdown("### Severity Level")
    severities = ["All", "Critical", "High", "Medium", "Low"]
    selected_severity = st.sidebar.selectbox("Select severity", severities, label_visibility="collapsed")
    
    # Time range filter
    st.sidebar.markdown("### Time Range")
    time_ranges = ["All Time", "Last Hour", "Last 24 Hours", "Last 7 Days", "Last 30 Days"]
    selected_time = st.sidebar.selectbox("Select time range", time_ranges, label_visibility="collapsed")
    
    return selected_type, selected_severity, selected_time

def apply_filters(df: pd.DataFrame, attack_type, severity, time_range):
    """Apply filters to dataframe."""
    if df.empty:
        return df
    
    filtered = df.copy()
    
    if attack_type != "All":
        filtered = filtered[filtered["attack_type"] == attack_type]
    
    if severity != "All":
        filtered = filtered[filtered["severity"] == severity]
    
    if time_range != "All Time":
        now = datetime.now()
        if time_range == "Last Hour":
            cutoff = now - timedelta(hours=1)
        elif time_range == "Last 24 Hours":
            cutoff = now - timedelta(days=1)
        elif time_range == "Last 7 Days":
            cutoff = now - timedelta(days=7)
        elif time_range == "Last 30 Days":
            cutoff = now - timedelta(days=30)
        else:
            cutoff = now - timedelta(days=365)
        filtered = filtered[filtered["timestamp"] >= cutoff]
    
    return filtered

# ═══════════════════════════════════════════════════════════════════════════
# DASHBOARD COMPONENTS
# ═══════════════════════════════════════════════════════════════════════════
def render_header():
    """Render dashboard header."""
    st.markdown('''
        <div class="professional-banner">
            <strong>NETWORK SECURITY MONITORING PLATFORM</strong> | Real-time Multi-Attack Detection & Analysis
        </div>
    ''', unsafe_allow_html=True)
    st.title("Attack Detection Dashboard")

def render_kpi_cards(df: pd.DataFrame):
    """Render KPI metric cards."""
    if df.empty:
        st.info("No attack data available. Run the honeypot and attack simulators to generate data.")
        return
    
    col1, col2, col3, col4, col5 = st.columns(5)
    
    with col1:
        st.metric("Total Attacks", f"{len(df):,}")
    
    with col2:
        unique_ips = df["ip_address"].nunique()
        st.metric("Unique Sources", f"{unique_ips:,}")
    
    with col3:
        attack_types = df["attack_type"].nunique()
        st.metric("Attack Vectors", attack_types)
    
    with col4:
        critical_count = len(df[df["severity"] == "Critical"])
        st.metric("Critical Threats", f"{critical_count:,}")
    
    with col5:
        high_count = len(df[df["severity"] == "High"])
        st.metric("High Severity", f"{high_count:,}")

def render_attack_type_metrics(df: pd.DataFrame):
    """Render attack-type-specific KPIs."""
    if df.empty:
        return
    
    st.subheader("Attack Type Distribution")
    
    # Get counts by attack type
    type_counts = df["attack_type"].value_counts()
    
    cols = st.columns(5)
    attack_types = [
        ("ssh", "SSH"),
        ("portscan", "Port Scan"),
        ("dns", "DNS"),
        ("arp", "ARP"),
        ("icmp", "ICMP")
    ]
    
    for i, (atype, label) in enumerate(attack_types):
        with cols[i]:
            count = type_counts.get(atype, 0)
            st.metric(label, f"{count:,}")

def render_charts(df: pd.DataFrame):
    """Render main charts."""
    if df.empty:
        return
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Attack Types")
        type_counts = df["attack_type"].value_counts()
        fig = px.bar(
            x=type_counts.index,
            y=type_counts.values,
            labels={"x": "Attack Type", "y": "Count"},
            color=type_counts.values,
            color_continuous_scale="Blues"
        )
        fig.update_layout(
            plot_bgcolor="#0d1117",
            paper_bgcolor="#0d1117",
            font_color="#e6edf3",
            showlegend=False,
            height=350
        )
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        st.subheader("Top Source IPs")
        ip_counts = df["ip_address"].value_counts().head(10)
        fig = px.bar(
            x=ip_counts.index,
            y=ip_counts.values,
            labels={"x": "IP Address", "y": "Attack Count"},
            color=ip_counts.values,
            color_continuous_scale="Reds"
        )
        fig.update_layout(
            plot_bgcolor="#0d1117",
            paper_bgcolor="#0d1117",
            font_color="#e6edf3",
            showlegend=False,
            height=350
        )
        st.plotly_chart(fig, use_container_width=True)

def render_severity_chart(df: pd.DataFrame):
    """Render severity distribution."""
    if df.empty:
        return
    
    st.subheader("Severity Distribution")
    
    # Check if severity column exists and has data
    if "severity" not in df.columns or df["severity"].isna().all():
        st.info("No severity data available")
        return
    
    severity_counts = df["severity"].value_counts()
    
    # Only show severities that have counts > 0
    if severity_counts.empty:
        st.info("No severity data available")
        return
    
    severity_colors = {
        "Critical": "#f85149",
        "High": "#ff8800", 
        "Medium": "#d4a72c",
        "Low": "#2ea043"
    }
    
    # Create pie chart with actual data only
    fig = px.pie(
        values=severity_counts.values,
        names=severity_counts.index,
        color=severity_counts.index,
        color_discrete_map=severity_colors
    )
    fig.update_layout(
        plot_bgcolor="#0d1117",
        paper_bgcolor="#0d1117",
        font_color="#e6edf3",
        height=350,
        showlegend=True
    )
    fig.update_traces(
        textposition='inside',
        textinfo='percent+label',
        marker=dict(line=dict(color='#0d1117', width=2))
    )
    st.plotly_chart(fig, use_container_width=True)

def render_timeline(df: pd.DataFrame):
    """Render attack timeline."""
    if df.empty:
        return
    
    st.subheader("Attack Timeline")
    
    # Group by hour
    df_timeline = df.copy()
    df_timeline["hour"] = df_timeline["timestamp"].dt.floor("h")
    
    # Create timeline by attack type
    timeline_data = df_timeline.groupby(["hour", "attack_type"]).size().reset_index(name="count")
    
    if not timeline_data.empty:
        fig = px.line(
            timeline_data,
            x="hour",
            y="count",
            color="attack_type",
            labels={"hour": "Time", "count": "Attack Count", "attack_type": "Type"},
            color_discrete_sequence=px.colors.qualitative.Set2
        )
        fig.update_layout(
            plot_bgcolor="#0d1117",
            paper_bgcolor="#0d1117",
            font_color="#e6edf3",
            height=350,
            legend=dict(
                orientation="h",
                yanchor="bottom",
                y=1.02,
                xanchor="right",
                x=1
            )
        )
        st.plotly_chart(fig, use_container_width=True)

def render_correlation_table(df: pd.DataFrame):
    """Render cross-attack correlation (IPs hitting multiple services)."""
    if df.empty:
        return
    
    st.subheader("Cross-Attack Correlation")
    st.markdown("IPs targeting multiple attack vectors:")
    
    # Find IPs that appear in multiple attack types
    ip_types = df.groupby("ip_address")["attack_type"].nunique()
    multi_vector = ip_types[ip_types > 1]
    
    if len(multi_vector) > 0:
        multi_df = df[df["ip_address"].isin(multi_vector.index)]
        summary = multi_df.groupby("ip_address").agg({
            "attack_type": lambda x: ", ".join(sorted(x.unique())),
            "timestamp": "count",
            "severity": lambda x: x.value_counts().index[0] if len(x) > 0 else "Unknown"
        }).rename(columns={
            "timestamp": "Total Attacks", 
            "attack_type": "Attack Vectors",
            "severity": "Max Severity"
        })
        summary = summary.sort_values("Total Attacks", ascending=False).head(10)
        st.dataframe(summary, use_container_width=True)
    else:
        st.info("No multi-vector attacks detected. All sources are targeting single attack types.")

def render_recent_attacks(df: pd.DataFrame):
    """Render recent attacks table."""
    if df.empty:
        return
    
    st.subheader("Recent Attack Sessions")
    
    # Show most recent attacks
    display_cols = ["timestamp", "ip_address", "attack_type", "predicted_label", "severity", "session_duration"]
    available_cols = [c for c in display_cols if c in df.columns]
    
    recent = df.sort_values("timestamp", ascending=False).head(20)[available_cols].copy()
    
    # Format timestamp
    if "timestamp" in recent.columns:
        recent["timestamp"] = recent["timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S")
    
    # Format duration
    if "session_duration" in recent.columns:
        recent["session_duration"] = recent["session_duration"].apply(lambda x: f"{x:.2f}s" if pd.notna(x) else "N/A")
    
    st.dataframe(recent, use_container_width=True)

def render_full_data(df: pd.DataFrame):
    """Render full data explorer."""
    with st.expander("FULL DATASET EXPLORER"):
        if not df.empty:
            st.dataframe(df, use_container_width=True)
        else:
            st.info("No data available")

# ═══════════════════════════════════════════════════════════════════════════
# MAIN DASHBOARD
# ═══════════════════════════════════════════════════════════════════════════
def main():
    """Main dashboard entry point."""
    render_header()
    
    # Load data
    df = load_attack_data()
    
    # Sidebar filters
    attack_type, severity, time_range = render_sidebar(df)
    
    # Apply filters
    filtered_df = apply_filters(df, attack_type, severity, time_range)
    
    # Show filter status
    if attack_type != "All" or severity != "All" or time_range != "All Time":
        st.info(f"Displaying {len(filtered_df):,} of {len(df):,} total records")
    
    # Render dashboard sections
    render_kpi_cards(filtered_df)
    st.divider()
    
    render_attack_type_metrics(filtered_df)
    st.divider()
    
    render_charts(filtered_df)
    st.divider()
    
    col1, col2 = st.columns(2)
    with col1:
        render_severity_chart(filtered_df)
    with col2:
        render_timeline(filtered_df)
    
    st.divider()
    render_correlation_table(filtered_df)
    
    st.divider()
    render_recent_attacks(filtered_df)
    
    render_full_data(filtered_df)
    
    # Footer
    st.markdown("---")
    st.markdown(
        '<div style="text-align: center; color: #8b949e; font-size: 0.85em; font-weight: 500;">'
        'Network Security Monitoring Platform | Educational Project'
        '</div>',
        unsafe_allow_html=True
    )


if __name__ == "__main__":
    main()
