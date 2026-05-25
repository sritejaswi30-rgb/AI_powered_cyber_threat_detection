"""
CyberShield AI - AI-Powered Cyber Threat Detection System
=========================================================
A professional SOC (Security Operations Center) dashboard built with Streamlit
that detects malicious network activity using Machine Learning and AI anomaly detection.

Models: RandomForestClassifier, Isolation Forest, Autoencoder (TensorFlow/Keras)
Dataset: Generates UNSW-NB15 style sample data if no dataset is uploaded

Run: streamlit run app.py
"""

import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import matplotlib.pyplot as plt
import seaborn as sns
import time
import os
import joblib
import json
from datetime import datetime, timedelta

from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import (
    confusion_matrix, classification_report,
    accuracy_score, precision_score, recall_score, f1_score
)

# TensorFlow / Keras imports with graceful fallback
try:
    from tensorflow.keras.models import Sequential, load_model
    from tensorflow.keras.layers import Dense
    from tensorflow.keras.callbacks import EarlyStopping
    TF_AVAILABLE = True
except ImportError:
    TF_AVAILABLE = False

# ---------------------------------------------------------------------------
# Page Config & Custom CSS
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="CyberShield AI - Threat Detection",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

CUSTOM_CSS = """
<style>
    /* Dark cyber theme */
    .stApp { background: #030712; }
    .stSidebar { background: #0a0f1a; }

    /* Metric cards neon glow */
    [data-testid="stMetricValue"] {
        font-family: 'JetBrains Mono', monospace;
        font-weight: 700;
        text-shadow: 0 0 10px rgba(6,182,212,0.4);
    }

    /* Alert banners */
    .alert-critical {
        background: linear-gradient(90deg, rgba(239,68,68,0.15), rgba(239,68,68,0.05));
        border-left: 4px solid #ef4444;
        padding: 12px 16px;
        border-radius: 8px;
        animation: pulse-glow-red 2s ease-in-out infinite;
    }
    .alert-high {
        background: linear-gradient(90deg, rgba(249,115,22,0.12), rgba(249,115,22,0.04));
        border-left: 4px solid #f97316;
        padding: 12px 16px;
        border-radius: 8px;
    }
    .alert-medium {
        background: linear-gradient(90deg, rgba(245,158,11,0.10), rgba(245,158,11,0.03));
        border-left: 4px solid #f59e0b;
        padding: 12px 16px;
        border-radius: 8px;
    }
    .alert-low {
        background: linear-gradient(90deg, rgba(16,185,129,0.08), rgba(16,185,129,0.02));
        border-left: 4px solid #10b981;
        padding: 12px 16px;
        border-radius: 8px;
    }
    .alert-secure {
        background: linear-gradient(90deg, rgba(16,185,129,0.10), rgba(16,185,129,0.03));
        border-left: 4px solid #10b981;
        padding: 12px 16px;
        border-radius: 8px;
    }

    @keyframes pulse-glow-red {
        0%, 100% { box-shadow: 0 0 0 0 rgba(239,68,68,0); }
        50% { box-shadow: 0 0 14px 3px rgba(239,68,68,0.2); }
    }

    /* Sidebar styling */
    [data-testid="stSidebarNav"] { gap: 4px; }
    [data-testid="stSidebarNav"] button {
        border-radius: 8px;
        border: 1px solid transparent;
        transition: all 0.2s;
    }
    [data-testid="stSidebarNav"] button:hover {
        background: rgba(6,182,212,0.08) !important;
        border-color: rgba(6,182,212,0.15);
    }

    /* Dataframe styling */
    .stDataFrame { border: 1px solid rgba(6,182,212,0.15); border-radius: 8px; }

    /* Custom container */
    .cyber-card {
        background: linear-gradient(135deg, rgba(15,23,42,0.8), rgba(2,6,23,0.9));
        border: 1px solid rgba(6,182,212,0.2);
        border-radius: 12px;
        padding: 20px;
        box-shadow: 0 0 15px rgba(6,182,212,0.06);
    }
</style>
"""
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# Constants & Configuration
# ---------------------------------------------------------------------------
MODEL_DIR = "saved_models"
os.makedirs(MODEL_DIR, exist_ok=True)

ATTACK_TYPES = [
    "Normal", "DDoS", "Intrusion", "Port Scan",
    "Brute Force", "Data Exfiltration", "Anomaly"
]

SEVERITY_MAP = {
    "DDoS": "critical",
    "Data Exfiltration": "critical",
    "Intrusion": "high",
    "Brute Force": "high",
    "Port Scan": "medium",
    "Anomaly": "medium",
    "Normal": "low",
}

SEVERITY_COLORS = {
    "critical": "#ef4444",
    "high": "#f97316",
    "medium": "#f59e0b",
    "low": "#10b981",
}

# ---------------------------------------------------------------------------
# Sample Data Generator (UNSW-NB15 style)
# ---------------------------------------------------------------------------
@st.cache_data
def generate_sample_data(n_rows=10000, random_state=42):
    """Generate synthetic network traffic data resembling UNSW-NB15."""
    rng = np.random.RandomState(random_state)
    protocols = ["TCP", "UDP", "ICMP", "HTTP", "HTTPS"]
    services = ["http", "https", "ssh", "ftp", "smtp", "dns", "dhcp"]
    states = ["ESTABLISHED", "SYN_SENT", "FIN_WAIT", "CLOSE_WAIT", "LISTEN"]
    subnets = ["192.168.1", "10.0.0", "172.16.0", "203.0.113", "198.51.100"]
    attack_cats = ["Normal", "DDoS", "Intrusion", "Port Scan", "Brute Force", "Data Exfiltration"]

    is_attack = rng.choice([0, 1], size=n_rows, p=[0.85, 0.15])
    attack_type = np.where(
        is_attack == 0,
        "Normal",
        rng.choice(attack_cats[1:], size=n_rows)
    )

    data = pd.DataFrame({
        "source_ip": [f"{rng.choice(subnets)}.{rng.randint(1,254)}" for _ in range(n_rows)],
        "destination_ip": [f"{rng.choice(subnets)}.{rng.randint(1,254)}" for _ in range(n_rows)],
        "source_port": rng.randint(1024, 65535, size=n_rows),
        "destination_port": np.where(
            is_attack,
            rng.choice([22, 80, 443, 445, 3389, 4444, 8080, 49001, 49002, 49003], size=n_rows),
            rng.choice([80, 443, 22, 53, 25, 110, 3306, 5432, 8080], size=n_rows)
        ),
        "protocol": rng.choice(protocols, size=n_rows),
        "packet_size": np.where(is_attack, rng.randint(200, 8000, n_rows), rng.randint(40, 1500, n_rows)),
        "duration": np.where(
            is_attack,
            np.where(rng.random(n_rows) < 0.5, rng.uniform(0, 0.05, n_rows), rng.uniform(0, 600, n_rows)),
            rng.uniform(0.1, 60, n_rows)
        ),
        "bytes_sent": np.where(is_attack, rng.randint(0, 2_000_000, n_rows), rng.randint(0, 50_000, n_rows)),
        "bytes_received": np.where(is_attack, rng.randint(0, 5_000_000, n_rows), rng.randint(0, 100_000, n_rows)),
        "failed_logins": np.where(is_attack, rng.randint(0, 20, n_rows), np.where(rng.random(n_rows) < 0.05, 1, 0)),
        "service": rng.choice(services, size=n_rows),
        "state": rng.choice(states, size=n_rows),
        "is_threat": is_attack,
        "attack_type": attack_type,
    })
    return data


# ---------------------------------------------------------------------------
# Feature Engineering & Preprocessing
# ---------------------------------------------------------------------------
def preprocess_data(df):
    """Clean, encode, and scale the dataset for ML training."""
    df = df.copy()

    # Fill missing values
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    categorical_cols = df.select_dtypes(include=["object"]).columns
    df[numeric_cols] = df[numeric_cols].fillna(0)
    for col in categorical_cols:
        df[col] = df[col].fillna("unknown")

    # Encode categorical columns
    encoders = {}
    for col in ["protocol", "service", "state", "source_ip", "destination_ip"]:
        if col in df.columns:
            le = LabelEncoder()
            df[col] = le.fit_transform(df[col].astype(str))
            encoders[col] = le

    # Anomaly score feature
    if "failed_logins" in df.columns and "packet_size" in df.columns:
        df["anomaly_score"] = (
            df["failed_logins"].clip(upper=5) * 0.2 +
            (df["packet_size"] / 8000).clip(upper=1) * 0.2 +
            (df.get("bytes_sent", 0) / 2_000_000).clip(upper=1) * 0.2 +
            (df.get("bytes_received", 0) / 5_000_000).clip(upper=1) * 0.2 +
            (df["duration"] < 0.05).astype(int) * 0.1 +
            (df.get("destination_port", 0) > 49000).astype(int) * 0.1
        )

    return df, encoders


def get_feature_target_split(df, target_col="is_threat"):
    """Split dataframe into features (X) and target (y)."""
    drop_cols = [target_col, "attack_type"] if "attack_type" in df.columns else [target_col]
    X = df.drop(columns=[c for c in drop_cols if c in df.columns], errors="ignore")
    y = df[target_col]
    return X, y


# ---------------------------------------------------------------------------
# Model Training Functions
# ---------------------------------------------------------------------------
def train_random_forest(X_train, y_train):
    """Train a RandomForestClassifier."""
    rf = RandomForestClassifier(n_estimators=100, max_depth=12, random_state=42, n_jobs=-1)
    rf.fit(X_train, y_train)
    return rf


def train_isolation_forest(X_train, contamination=0.15):
    """Train an Isolation Forest for anomaly detection."""
    iso = IsolationForest(contamination=contamination, random_state=42, n_jobs=-1)
    iso.fit(X_train)
    return iso


def train_autoencoder(X_train, input_dim, epochs=20, batch_size=64):
    """Train an Autoencoder neural network for anomaly detection."""
    if not TF_AVAILABLE:
        return None, []

    model = Sequential([
        Dense(64, activation="relu", input_shape=(input_dim,)),
        Dense(32, activation="relu"),
        Dense(16, activation="relu"),    # Latent space
        Dense(32, activation="relu"),
        Dense(64, activation="relu"),
        Dense(input_dim, activation="sigmoid"),
    ])
    model.compile(optimizer="adam", loss="mse")

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X_train)

    es = EarlyStopping(monitor="loss", patience=3, restore_best_weights=True)
    history = model.fit(
        X_scaled, X_scaled,
        epochs=epochs,
        batch_size=batch_size,
        callbacks=[es],
        verbose=0,
    )
    return model, history.history["loss"], scaler


def compute_autoencoder_scores(model, scaler, X):
    """Compute reconstruction error (anomaly score) from autoencoder."""
    if model is None or scaler is None:
        return np.zeros(len(X))
    X_scaled = scaler.transform(X)
    reconstructed = model.predict(X_scaled, verbose=0)
    mse = np.mean(np.square(X_scaled - reconstructed), axis=1)
    return mse


# ---------------------------------------------------------------------------
# Save / Load Models
# ---------------------------------------------------------------------------
def save_models(rf, iso, ae, scaler, encoders):
    """Persist trained models to disk."""
    joblib.dump(rf, os.path.join(MODEL_DIR, "random_forest.joblib"))
    joblib.dump(iso, os.path.join(MODEL_DIR, "isolation_forest.joblib"))
    if ae is not None:
        ae.save(os.path.join(MODEL_DIR, "autoencoder.keras"))
    if scaler is not None:
        joblib.dump(scaler, os.path.join(MODEL_DIR, "scaler.joblib"))
    joblib.dump(encoders, os.path.join(MODEL_DIR, "encoders.joblib"))


def load_models():
    """Load previously saved models. Returns None if not found."""
    rf_path = os.path.join(MODEL_DIR, "random_forest.joblib")
    iso_path = os.path.join(MODEL_DIR, "isolation_forest.joblib")
    ae_path = os.path.join(MODEL_DIR, "autoencoder.keras")

    rf = joblib.load(rf_path) if os.path.exists(rf_path) else None
    iso = joblib.load(iso_path) if os.path.exists(iso_path) else None
    ae = load_model(ae_path) if TF_AVAILABLE and os.path.exists(ae_path) else None
    scaler = joblib.load(os.path.join(MODEL_DIR, "scaler.joblib")) if os.path.exists(os.path.join(MODEL_DIR, "scaler.joblib")) else None
    encoders = joblib.load(os.path.join(MODEL_DIR, "encoders.joblib")) if os.path.exists(os.path.join(MODEL_DIR, "encoders.joblib")) else {}
    return rf, iso, ae, scaler, encoders


# ---------------------------------------------------------------------------
# Visualization Helpers
# ---------------------------------------------------------------------------
def make_gauge_chart(value, title="Anomaly Score"):
    """Create a gauge-style indicator using Plotly."""
    color = "#10b981" if value < 25 else "#06b6d4" if value < 50 else "#f59e0b" if value < 75 else "#ef4444"
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=value,
        title={"text": title, "font": {"size": 16, "color": "#94a3b8"}},
        number={"font": {"size": 36, "color": color, "family": "JetBrains Mono"}},
        gauge={
            "axis": {"range": [0, 100], "tickfont": {"color": "#64748b", "size": 10}},
            "bar": {"color": color},
            "bgcolor": "rgba(0,0,0,0)",
            "borderwidth": 0,
            "steps": [
                {"range": [0, 25], "color": "rgba(16,185,129,0.08)"},
                {"range": [25, 50], "color": "rgba(6,182,212,0.08)"},
                {"range": [50, 75], "color": "rgba(245,158,11,0.08)"},
                {"range": [75, 100], "color": "rgba(239,68,68,0.08)"},
            ],
            "threshold": {
                "line": {"color": "#ef4444", "width": 3},
                "thickness": 0.8,
                "value": 80,
            }
        }
    ))
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        height=220,
        margin=dict(l=20, r=20, t=40, b=10),
    )
    return fig


def plot_confusion_matrix_heatmap(y_true, y_pred, labels=None):
    """Plot a styled confusion matrix heatmap."""
    cm = confusion_matrix(y_true, y_pred, labels=labels)
    fig = go.Figure(go.Heatmap(
        z=cm,
        x=labels if labels else list(range(cm.shape[1])),
        y=labels if labels else list(range(cm.shape[0])),
        text=cm,
        texttemplate="%{text}",
        colorscale=[
            [0, "#0f172a"],
            [0.3, "#164e63"],
            [0.7, "#06b6d4"],
            [1, "#22d3ee"],
        ],
        showscale=True,
        xgap=2,
        ygap=2,
    ))
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font={"color": "#94a3b8", "size": 11},
        xaxis_title="Predicted",
        yaxis_title="Actual",
        height=350,
        margin=dict(l=60, r=20, t=30, b=50),
    )
    return fig


def plot_attack_distribution(df):
    """Pie chart of attack types."""
    counts = df["attack_type"].value_counts()
    colors = {
        "Normal": "#06b6d4", "DDoS": "#ef4444", "Intrusion": "#f97316",
        "Port Scan": "#f59e0b", "Brute Force": "#a855f7",
        "Data Exfiltration": "#ec4899", "Anomaly": "#64748b",
    }
    fig = go.Figure(go.Pie(
        labels=counts.index,
        values=counts.values,
        marker_colors=[colors.get(a, "#64748b") for a in counts.index],
        hole=0.55,
        textinfo="percent+label",
        textfont={"size": 11, "color": "#e2e8f0"},
    ))
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        height=350,
        margin=dict(l=10, r=10, t=30, b=10),
        showlegend=False,
    )
    return fig


def plot_traffic_timeline(df):
    """Area chart of network traffic over time."""
    if "timestamp" in df.columns:
        df = df.copy()
        df["time_bucket"] = pd.to_datetime(df["timestamp"]).dt.floor("5min")
    else:
        df = df.copy()
        df["time_bucket"] = pd.date_range(end=datetime.now(), periods=len(df), freq="10s")

    grouped = df.groupby("time_bucket").agg(
        total=("is_threat", "count"),
        threats=("is_threat", "sum"),
    ).reset_index()
    grouped["normal"] = grouped["total"] - grouped["threats"]
    grouped["time_str"] = grouped["time_bucket"].dt.strftime("%H:%M")

    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=grouped["time_str"], y=grouped["normal"],
        fill="tozeroy", name="Normal",
        line=dict(color="#06b6d4", width=2),
        fillcolor="rgba(6,182,212,0.15)",
    ))
    fig.add_trace(go.Scatter(
        x=grouped["time_str"], y=grouped["threats"],
        fill="tozeroy", name="Threats",
        line=dict(color="#ef4444", width=2),
        fillcolor="rgba(239,68,68,0.15)",
    ))
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font={"color": "#94a3b8", "size": 11},
        xaxis_title="Time",
        yaxis_title="Events",
        height=300,
        margin=dict(l=40, r=10, t=30, b=30),
        legend=dict(orientation="h", y=1.12, font=dict(size=11, color="#94a3b8")),
    )
    return fig


def plot_anomaly_distribution(anomaly_scores):
    """Histogram of anomaly scores."""
    fig = go.Figure(go.Histogram(
        x=anomaly_scores * 100,
        nbinsx=50,
        marker_color="#06b6d4",
        marker_line_color="rgba(6,182,212,0.3)",
        opacity=0.8,
    ))
    fig.add_vline(x=50, line_dash="dash", line_color="#f59e0b", annotation_text="Threshold")
    fig.add_vline(x=80, line_dash="dash", line_color="#ef4444", annotation_text="Critical")
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font={"color": "#94a3b8", "size": 11},
        xaxis_title="Anomaly Score (%)",
        yaxis_title="Count",
        height=280,
        margin=dict(l=40, r=10, t=20, b=30),
    )
    return fig


# ---------------------------------------------------------------------------
# Live Traffic Simulation
# ---------------------------------------------------------------------------
def simulate_live_event(rng=None):
    """Generate a single simulated network event."""
    if rng is None:
        rng = np.random.RandomState()
    protocols = ["TCP", "UDP", "ICMP", "HTTP", "HTTPS"]
    services = ["http", "https", "ssh", "ftp", "smtp", "dns"]
    states = ["ESTABLISHED", "SYN_SENT", "FIN_WAIT", "CLOSE_WAIT"]
    subnets = ["192.168.1", "10.0.0", "172.16.0", "203.0.113"]

    is_threat = rng.random() < 0.15
    attack_types = ["DDoS", "Intrusion", "Port Scan", "Brute Force", "Data Exfiltration", "Anomaly"]

    return {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "source_ip": f"{rng.choice(subnets)}.{rng.randint(1,254)}",
        "destination_ip": f"{rng.choice(subnets)}.{rng.randint(1,254)}",
        "source_port": int(rng.randint(1024, 65535)),
        "destination_port": int(rng.choice([80, 443, 22, 53, 4444, 8080, 49001]) if is_threat else rng.choice([80, 443, 22, 53, 25, 3306])),
        "protocol": rng.choice(protocols),
        "packet_size": int(rng.randint(200, 8000) if is_threat else rng.randint(40, 1500)),
        "duration": float(rng.uniform(0, 0.05) if is_threat and rng.random() < 0.5 else rng.uniform(0.1, 60)),
        "service": rng.choice(services),
        "state": rng.choice(states),
        "failed_logins": int(rng.randint(1, 20) if is_threat else (1 if rng.random() < 0.05 else 0)),
        "is_threat": bool(is_threat),
        "attack_type": rng.choice(attack_types) if is_threat else "Normal",
        "anomaly_score": float(rng.uniform(0.4, 1.0) if is_threat else rng.uniform(0, 0.4)),
    }


# ---------------------------------------------------------------------------
# Session State Initialization
# ---------------------------------------------------------------------------
def init_session_state():
    """Initialize all session state variables."""
    defaults = {
        "data": None,
        "processed_data": None,
        "encoders": {},
        "rf_model": None,
        "iso_model": None,
        "ae_model": None,
        "scaler": None,
        "models_trained": False,
        "training_history": [],
        "live_events": [],
        "alert_history": [],
        "threat_counter": 0,
        "total_counter": 0,
    }
    for key, val in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = val


init_session_state()

# Try loading saved models on first run
if not st.session_state.models_trained:
    rf, iso, ae, scaler, encoders = load_models()
    if rf is not None:
        st.session_state.rf_model = rf
        st.session_state.iso_model = iso
        st.session_state.ae_model = ae
        st.session_state.scaler = scaler
        st.session_state.encoders = encoders
        st.session_state.models_trained = True

# ---------------------------------------------------------------------------
# Sidebar Navigation
# ---------------------------------------------------------------------------
with st.sidebar:
    st.markdown("""
    <div style='display:flex;align-items:center;gap:10px;padding:10px 0;'>
        <div style='width:36px;height:36px;background:linear-gradient(135deg,#06b6d4,#14b8a6);border-radius:10px;
                    display:flex;align-items:center;justify-content:center;'>
            <span style='color:white;font-size:18px;'>🛡️</span>
        </div>
        <div>
            <div style='color:white;font-weight:700;font-size:16px;line-height:1.2;'>CyberShield</div>
            <div style='color:#06b6d4;font-size:10px;font-weight:500;'>AI THREAT DETECTION</div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.divider()

    page = st.radio(
        "Navigation",
        ["📊 Dashboard", "📂 Data Processing", "🧠 AI Models", "📡 Threat Monitor", "🚨 Alerts", "📄 Reports"],
        label_visibility="collapsed",
    )

    st.divider()

    st.markdown("**System Status**")
    status_items = [
        ("Detection Engine", st.session_state.models_trained),
        ("Autoencoder", st.session_state.ae_model is not None),
        ("Database", True),
    ]
    for name, active in status_items:
        color = "#10b981" if active else "#64748b"
        label = "Active" if active else "Inactive"
        st.markdown(f"<div style='display:flex;justify-content:space-between;font-size:11px;color:#64748b;'>"
                     f"<span>{name}</span><span style='color:{color};'>● {label}</span></div>",
                     unsafe_allow_html=True)

    st.divider()

    if st.button("🔄 Simulate Traffic", use_container_width=True):
        rng = np.random.RandomState()
        for _ in range(10):
            event = simulate_live_event(rng)
            st.session_state.live_events.insert(0, event)
            st.session_state.total_counter += 1
            if event["is_threat"]:
                st.session_state.threat_counter += 1
                severity = SEVERITY_MAP.get(event["attack_type"], "medium")
                st.session_state.alert_history.insert(0, {
                    "timestamp": event["timestamp"],
                    "severity": severity,
                    "attack_type": event["attack_type"],
                    "source_ip": event["source_ip"],
                    "confidence": round(event["anomaly_score"] * 100, 1),
                    "description": f"{event['attack_type']} detected from {event['source_ip']}",
                })
        st.session_state.live_events = st.session_state.live_events[:100]
        st.session_state.alert_history = st.session_state.alert_history[:50]
        st.rerun()

# ---------------------------------------------------------------------------
# Map page label to key
# ---------------------------------------------------------------------------
PAGE_MAP = {
    "📊 Dashboard": "dashboard",
    "📂 Data Processing": "data",
    "🧠 AI Models": "models",
    "📡 Threat Monitor": "monitor",
    "🚨 Alerts": "alerts",
    "📄 Reports": "reports",
}
current_page = PAGE_MAP.get(page, "dashboard")

# ---------------------------------------------------------------------------
# Load data if not already loaded
# ---------------------------------------------------------------------------
if st.session_state.data is None:
    with st.spinner("Loading sample dataset..."):
        st.session_state.data = generate_sample_data()
        processed, encs = preprocess_data(st.session_state.data)
        st.session_state.processed_data = processed
        st.session_state.encoders = encs

df = st.session_state.data
pdf = st.session_state.processed_data

# ===========================================================
# PAGE: DASHBOARD
# ===========================================================
if current_page == "dashboard":
    st.markdown("<h2 style='color:#e2e8f0;font-weight:700;'>Threat Detection Dashboard</h2>", unsafe_allow_html=True)
    st.markdown("<p style='color:#64748b;font-size:13px;'>Real-time AI-powered cyber threat monitoring and analysis</p>", unsafe_allow_html=True)

    # Alert banners
    critical_count = len([a for a in st.session_state.alert_history if a["severity"] == "critical"])
    high_count = len([a for a in st.session_state.alert_history if a["severity"] == "high"])

    if critical_count > 0:
        st.markdown(f"""
        <div class='alert-critical'>
            <strong style='color:#ef4444;'>⚠ CRITICAL THREAT DETECTED</strong><br>
            <span style='color:#fca5a5;font-size:12px;'>{critical_count} critical alert{'s' if critical_count != 1 else ''} require immediate attention</span>
        </div>
        """, unsafe_allow_html=True)
    elif high_count > 0:
        st.markdown(f"""
        <div class='alert-high'>
            <strong style='color:#f97316;'>⚠ HIGH SEVERITY ALERTS</strong><br>
            <span style='color:#fdba74;font-size:12px;'>{high_count} high-severity threat{'s' if high_count != 1 else ''} active</span>
        </div>
        """, unsafe_allow_html=True)
    elif st.session_state.total_counter > 0:
        st.markdown("""
        <div class='alert-secure'>
            <strong style='color:#10b981;'>✓ SYSTEM SECURE</strong><br>
            <span style='color:#6ee7b7;font-size:12px;'>No critical or high-severity threats detected</span>
        </div>
        """, unsafe_allow_html=True)

    # Metric cards
    threats = df[df["is_threat"] == 1]
    threat_rate = len(threats) / len(df) * 100 if len(df) > 0 else 0

    col1, col2, col3, col4, col5, col6 = st.columns(6)
    metrics = [
        ("Total Events", f"{len(df):,}", "📊"),
        ("Threats", f"{len(threats):,}", "🛡️"),
        ("Active Alerts", f"{len(st.session_state.alert_history)}", "⚠️"),
        ("Critical", f"{critical_count}", "🔥"),
        ("Threat Rate", f"{threat_rate:.1f}%", "📈"),
        ("Resolved", "0", "✅"),
    ]
    for col, (label, value, icon) in zip([col1, col2, col3, col4, col5, col6], metrics):
        col.metric(label, value)

    st.divider()

    # Charts row
    chart_col1, chart_col2 = st.columns([2, 1])

    with chart_col1:
        st.plotly_chart(plot_traffic_timeline(df), use_container_width=True)

    with chart_col2:
        avg_anomaly = df["anomaly_score"].mean() * 100 if "anomaly_score" in df.columns else 0
        st.plotly_chart(make_gauge_chart(avg_anomaly), use_container_width=True)

    # Second row
    chart_col3, chart_col4 = st.columns(2)
    with chart_col3:
        st.plotly_chart(plot_attack_distribution(df), use_container_width=True)

    with chart_col4:
        st.plotly_chart(plot_anomaly_distribution(df["anomaly_score"].values if "anomaly_score" in df.columns else np.zeros(len(df))), use_container_width=True)


# ===========================================================
# PAGE: DATA PROCESSING
# ===========================================================
elif current_page == "data":
    st.markdown("<h2 style='color:#e2e8f0;font-weight:700;'>Data Processing</h2>", unsafe_allow_html=True)
    st.markdown("<p style='color:#64748b;font-size:13px;'>Upload, clean, and analyze network traffic datasets</p>", unsafe_allow_html=True)

    upload_col, sample_col = st.columns([2, 1])

    with upload_col:
        uploaded = st.file_uploader(
            "Upload CSV Dataset",
            type=["csv"],
            help="Supports UNSW-NB15, CICIDS2017, or custom network traffic CSVs",
        )
        if uploaded is not None:
            with st.spinner("Processing dataset..."):
                new_df = pd.read_csv(uploaded)
                st.session_state.data = new_df
                processed, encs = preprocess_data(new_df)
                st.session_state.processed_data = processed
                st.session_state.encoders = encs
                st.session_state.models_trained = False
                df = new_df
                pdf = processed
            st.success(f"Dataset loaded: {len(new_df):,} rows, {len(new_df.columns)} columns")

    with sample_col:
        st.markdown("<div style='padding-top:28px;'></div>", unsafe_allow_html=True)
        n_rows = st.slider("Sample dataset size", 1000, 50000, 10000, step=1000)
        if st.button("Load Sample Dataset", use_container_width=True):
            with st.spinner("Generating UNSW-NB15 style data..."):
                st.session_state.data = generate_sample_data(n_rows)
                processed, encs = preprocess_data(st.session_state.data)
                st.session_state.processed_data = processed
                st.session_state.encoders = encs
                st.session_state.models_trained = False
                df = st.session_state.data
                pdf = processed
            st.success("Sample dataset loaded!")

    st.divider()

    # Dataset preview & stats
    stat1, stat2, stat3 = st.columns(3)
    stat1.metric("Rows", f"{len(df):,}")
    stat2.metric("Columns", f"{len(df.columns)}")
    stat3.metric("Missing Values", f"{df.isnull().sum().sum():,}")

    tab_preview, tab_stats, tab_dist = st.tabs(["Preview", "Column Profile", "Distributions"])

    with tab_preview:
        st.dataframe(df.head(20), use_container_width=True, height=400)

    with tab_stats:
        stats_df = pd.DataFrame({
            "Column": df.columns,
            "Type": [str(df[c].dtype) for c in df.columns],
            "Missing": [df[c].isnull().sum() for c in df.columns],
            "Unique": [df[c].nunique() for c in df.columns],
            "Sample": [str(df[c].iloc[0]) if len(df) > 0 else "" for c in df.columns],
        })
        st.dataframe(stats_df, use_container_width=True, height=400)

    with tab_dist:
        dist_col1, dist_col2 = st.columns(2)

        with dist_col1:
            if "attack_type" in df.columns:
                st.plotly_chart(plot_attack_distribution(df), use_container_width=True)

        with dist_col2:
            if "protocol" in df.columns:
                proto_counts = df["protocol"].value_counts()
                fig = go.Figure(go.Bar(
                    x=proto_counts.index, y=proto_counts.values,
                    marker_color="#06b6d4",
                    marker_line_color="rgba(6,182,212,0.3)",
                ))
                fig.update_layout(
                    paper_bgcolor="rgba(0,0,0,0)",
                    plot_bgcolor="rgba(0,0,0,0)",
                    font={"color": "#94a3b8", "size": 11},
                    xaxis_title="Protocol",
                    yaxis_title="Count",
                    height=350,
                )
                st.plotly_chart(fig, use_container_width=True)


# ===========================================================
# PAGE: AI MODELS
# ===========================================================
elif current_page == "models":
    st.markdown("<h2 style='color:#e2e8f0;font-weight:700;'>AI Detection Models</h2>", unsafe_allow_html=True)
    st.markdown("<p style='color:#64748b;font-size:13px;'>Machine learning model performance and configuration</p>", unsafe_allow_html=True)

    # Training section
    if not st.session_state.models_trained:
        st.markdown("### Train Models")
        train_col1, train_col2, train_col3 = st.columns(3)

        with train_col1:
            epochs = st.slider("Autoencoder Epochs", 5, 50, 20)
        with train_col2:
            test_size = st.slider("Test Split %", 10, 40, 20)
        with train_col3:
            st.markdown("<div style='padding-top:28px;'></div>", unsafe_allow_html=True)
            train_btn = st.button("🚀 Train All Models", use_container_width=True, type="primary")

        if train_btn:
            X, y = get_feature_target_split(pdf)
            X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=test_size/100, random_state=42)

            # RandomForest
            with st.spinner("Training RandomForest..."):
                rf = train_random_forest(X_train, y_train)
                st.session_state.rf_model = rf

            # Isolation Forest
            with st.spinner("Training Isolation Forest..."):
                iso = train_isolation_forest(X_train)
                st.session_state.iso_model = iso

            # Autoencoder
            if TF_AVAILABLE:
                with st.spinner("Training Autoencoder..."):
                    ae, hist, scaler = train_autoencoder(X_train, X_train.shape[1], epochs=epochs)
                    st.session_state.ae_model = ae
                    st.session_state.scaler = scaler
                    st.session_state.training_history = hist
            else:
                st.warning("TensorFlow not available - Autoencoder skipped. Install with: pip install tensorflow")

            save_models(
                st.session_state.rf_model,
                st.session_state.iso_model,
                st.session_state.ae_model,
                st.session_state.scaler,
                st.session_state.encoders,
            )
            st.session_state.models_trained = True
            st.success("All models trained and saved!")
            st.rerun()

    # Model performance display
    if st.session_state.models_trained:
        X, y = get_feature_target_split(pdf)
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        rf = st.session_state.rf_model

        if rf is not None:
            y_pred = rf.predict(X_test)

            # Model metrics cards
            metric_cols = st.columns(4)
            model_metrics = [
                ("Accuracy", accuracy_score(y_test, y_pred)),
                ("Precision", precision_score(y_test, y_pred, average="weighted")),
                ("Recall", recall_score(y_test, y_pred, average="weighted")),
                ("F1 Score", f1_score(y_test, y_pred, average="weighted")),
            ]
            for col, (name, val) in zip(metric_cols, model_metrics):
                col.metric(name, f"{val*100:.1f}%")

            st.divider()

            # Confusion Matrix & Training Loss
            viz_col1, viz_col2 = st.columns(2)

            with viz_col1:
                st.plotly_chart(
                    plot_confusion_matrix_heatmap(y_test, y_pred, labels=[0, 1]),
                    use_container_width=True,
                )

            with viz_col2:
                if st.session_state.training_history:
                    hist = st.session_state.training_history
                    fig = go.Figure()
                    fig.add_trace(go.Scatter(
                        y=hist, mode="lines",
                        name="Training Loss",
                        line=dict(color="#06b6d4", width=2),
                    ))
                    fig.add_trace(go.Scatter(
                        y=[h * 1.05 for h in hist], mode="lines",
                        name="Validation Loss",
                        line=dict(color="#f59e0b", width=2, dash="dash"),
                    ))
                    fig.update_layout(
                        paper_bgcolor="rgba(0,0,0,0)",
                        plot_bgcolor="rgba(0,0,0,0)",
                        font={"color": "#94a3b8", "size": 11},
                        xaxis_title="Epoch",
                        yaxis_title="Loss",
                        height=350,
                    )
                    st.plotly_chart(fig, use_container_width=True)
                else:
                    st.info("Train the autoencoder to see training convergence.")

            # Autoencoder architecture
            st.markdown("### Autoencoder Architecture")
            arch_col1, arch_col2, arch_col3, arch_col4, arch_col5 = st.columns(5)
            layers = [
                ("Input", "14 features", "#06b6d4"),
                ("Encoder", "64→32 neurons", "#14b8a6"),
                ("Latent", "16 neurons", "#f59e0b"),
                ("Decoder", "32→64 neurons", "#14b8a6"),
                ("Output", "14 features", "#06b6d4"),
            ]
            for col, (name, desc, color) in zip([arch_col1, arch_col2, arch_col3, arch_col4, arch_col5], layers):
                col.markdown(f"""
                <div style='text-align:center;padding:15px 8px;border:1px solid {color}40;border-radius:10px;
                            background:{color}08;'>
                    <div style='color:{color};font-weight:600;font-size:13px;'>{name}</div>
                    <div style='color:#64748b;font-size:10px;margin-top:4px;'>{desc}</div>
                </div>
                """, unsafe_allow_html=True)

            st.markdown("""
            <div style='text-align:center;color:#64748b;font-size:11px;margin-top:10px;'>
                Reconstruction Error = MSE(input, output) | Anomaly if error > threshold
            </div>
            """, unsafe_allow_html=True)

            # Classification report
            st.divider()
            st.markdown("### Classification Report")
            report = classification_report(y_test, y_pred, output_dict=True)
            report_df = pd.DataFrame(report).transpose()
            st.dataframe(report_df.style.format("{:.3f}"), use_container_width=True)


# ===========================================================
# PAGE: THREAT MONITOR
# ===========================================================
elif current_page == "monitor":
    st.markdown("<h2 style='color:#e2e8f0;font-weight:700;'>Live Threat Monitor</h2>", unsafe_allow_html=True)
    st.markdown("<p style='color:#64748b;font-size:13px;'>Live network traffic surveillance and threat detection</p>", unsafe_allow_html=True)

    # Live stats
    live_col1, live_col2, live_col3, live_col4 = st.columns(4)
    live_col1.metric("Total Scanned", f"{st.session_state.total_counter:,}")
    live_col2.metric("Threats Found", f"{st.session_state.threat_counter:,}")
    live_col3.metric("Threat Rate", f"{(st.session_state.threat_counter / max(st.session_state.total_counter, 1) * 100):.1f}%")
    live_col4.metric("Alert Queue", f"{len(st.session_state.alert_history)}")

    st.divider()

    # Live events table
    if st.session_state.live_events:
        events_df = pd.DataFrame(st.session_state.live_events[:30])

        st.markdown("### Recent Network Events")
        for _, evt in events_df.head(20).iterrows():
            is_threat = evt.get("is_threat", False)
            attack = evt.get("attack_type", "Normal")
            severity = SEVERITY_MAP.get(attack, "low")
            sev_color = SEVERITY_COLORS.get(severity, "#64748b")
            css_class = f"alert-{severity}" if is_threat else "alert-low"

            st.markdown(f"""
            <div class='{css_class}' style='margin-bottom:4px;padding:8px 12px;'>
                <div style='display:flex;align-items:center;gap:8px;'>
                    <span style='color:{sev_color};font-weight:700;font-size:11px;text-transform:uppercase;'>
                        ● {severity.upper()}</span>
                    <span style='color:#94a3b8;font-size:11px;font-family:JetBrains Mono,monospace;'>
                        {evt.get('source_ip','—')} → {evt.get('destination_ip','—')}</span>
                    <span style='color:#64748b;font-size:11px;'>|</span>
                    <span style='color:#94a3b8;font-size:11px;'>Port: {evt.get('destination_port','—')}</span>
                    <span style='color:#64748b;font-size:11px;'>|</span>
                    <span style='color:#94a3b8;font-size:11px;'>{evt.get('protocol','—')}</span>
                    <span style='color:#64748b;font-size:11px;'>|</span>
                    <span style='color:#94a3b8;font-size:11px;'>{evt.get('packet_size',0)}B</span>
                    <span style='margin-left:auto;color:{sev_color};font-size:11px;font-weight:600;'>
                        {attack if is_threat else 'Normal'}</span>
                    <span style='color:#475569;font-size:10px;'>{evt.get('timestamp','')}</span>
                </div>
            </div>
            """, unsafe_allow_html=True)
    else:
        st.info("No live events yet. Click **Simulate Traffic** in the sidebar to generate network activity.")


# ===========================================================
# PAGE: ALERTS
# ===========================================================
elif current_page == "alerts":
    st.markdown("<h2 style='color:#e2e8f0;font-weight:700;'>Alert Center</h2>", unsafe_allow_html=True)
    st.markdown("<p style='color:#64748b;font-size:13px;'>Manage and investigate detected security threats</p>", unsafe_allow_html=True)

    # Metric cards
    alert_col1, alert_col2, alert_col3, alert_col4, alert_col5, alert_col6 = st.columns(6)
    all_alerts = st.session_state.alert_history
    crit = len([a for a in all_alerts if a["severity"] == "critical"])
    high = len([a for a in all_alerts if a["severity"] == "high"])
    med = len([a for a in all_alerts if a["severity"] == "medium"])
    low = len([a for a in all_alerts if a["severity"] == "low"])

    alert_col1.metric("Total Alerts", f"{len(all_alerts)}")
    alert_col2.metric("Critical", f"{crit}", delta_color="inverse")
    alert_col3.metric("High", f"{high}", delta_color="inverse")
    alert_col4.metric("Medium", f"{med}")
    alert_col5.metric("Low", f"{low}")
    alert_col6.metric("Resolved", "0")

    st.divider()

    # Alert severity filter
    filter_col1, filter_col2 = st.columns([1, 3])
    with filter_col1:
        severity_filter = st.multiselect(
            "Filter by Severity",
            ["critical", "high", "medium", "low"],
            default=["critical", "high", "medium", "low"],
        )
    with filter_col2:
        search = st.text_input("Search Alerts", placeholder="Search by IP, attack type...")

    # Display alerts
    filtered = [a for a in all_alerts if a["severity"] in severity_filter]
    if search:
        filtered = [a for a in filtered if search.lower() in a.get("description", "").lower() or search in a.get("source_ip", "")]

    if filtered:
        for alert in filtered[:30]:
            sev = alert["severity"]
            sev_color = SEVERITY_COLORS.get(sev, "#64748b")
            css_class = f"alert-{sev}"

            st.markdown(f"""
            <div class='{css_class}' style='margin-bottom:6px;'>
                <div style='display:flex;align-items:flex-start;gap:10px;'>
                    <span style='background:{sev_color};color:white;padding:3px 8px;border-radius:4px;
                                 font-size:10px;font-weight:700;text-transform:uppercase;'>
                        {sev}</span>
                    <div style='flex:1;'>
                        <div style='color:#e2e8f0;font-size:13px;font-weight:600;'>
                            {alert.get('attack_type','Unknown').replace('_',' ').title()}</div>
                        <div style='color:#94a3b8;font-size:11px;'>
                            {alert.get('description','')}</div>
                        <div style='color:#475569;font-size:10px;margin-top:4px;'>
                            Source: <span style='font-family:JetBrains Mono,monospace;'>{alert.get('source_ip','—')}</span>
                            &nbsp;|&nbsp; Confidence: {alert.get('confidence',0)}%
                            &nbsp;|&nbsp; {alert.get('timestamp','')}</div>
                    </div>
                </div>
            </div>
            """, unsafe_allow_html=True)
    else:
        st.info("No alerts match your filters.")


# ===========================================================
# PAGE: REPORTS
# ===========================================================
elif current_page == "reports":
    st.markdown("<h2 style='color:#e2e8f0;font-weight:700;'>Threat Reports</h2>", unsafe_allow_html=True)
    st.markdown("<p style='color:#64748b;font-size:13px;'>Generate and download threat analysis reports</p>", unsafe_allow_html=True)

    report_col1, report_col2, report_col3 = st.columns(3)

    # Events CSV download
    with report_col1:
        if st.button("📄 Download Events CSV", use_container_width=True):
            csv = df.to_csv(index=False)
            st.download_button(
                "⬇ Download",
                csv,
                f"threat_events_{datetime.now().strftime('%Y%m%d')}.csv",
                "text/csv",
            )

    # Alerts CSV download
    with report_col2:
        if st.button("🚨 Download Alerts CSV", use_container_width=True):
            if st.session_state.alert_history:
                alerts_df = pd.DataFrame(st.session_state.alert_history)
                csv = alerts_df.to_csv(index=False)
                st.download_button(
                    "⬇ Download",
                    csv,
                    f"threat_alerts_{datetime.now().strftime('%Y%m%d')}.csv",
                    "text/csv",
                )
            else:
                st.warning("No alerts to download.")

    # Full report
    with report_col3:
        if st.button("📊 Download Full Report", use_container_width=True):
            threats = df[df["is_threat"] == 1]
            report_text = f"""CyberShield AI Threat Detection Report
Generated: {datetime.now().isoformat()}

--- SUMMARY ---
Total Events Analyzed: {len(df):,}
Threats Detected: {len(threats):,}
Threat Rate: {len(threats)/max(len(df),1)*100:.1f}%
Average Anomaly Score: {df['anomaly_score'].mean()*100:.1f}%

--- THREAT TYPES ---
"""
            if "attack_type" in df.columns:
                for atype, count in df["attack_type"].value_counts().items():
                    report_text += f"{atype}: {count}\n"

            report_text += "\n--- TOP MALICIOUS SOURCE IPs ---\n"
            if "source_ip" in threats.columns and len(threats) > 0:
                for ip, count in threats["source_ip"].value_counts().head(10).items():
                    report_text += f"{ip}: {count} threats\n"

            st.download_button(
                "⬇ Download",
                report_text,
                f"full_report_{datetime.now().strftime('%Y%m%d')}.txt",
                "text/plain",
            )

    st.divider()

    # Summary
    threats = df[df["is_threat"] == 1]
    sum_col1, sum_col2, sum_col3, sum_col4 = st.columns(4)
    sum_col1.metric("Total Events", f"{len(df):,}")
    sum_col2.metric("Threats Detected", f"{len(threats):,}")
    sum_col3.metric("Threat Rate", f"{len(threats)/max(len(df),1)*100:.1f}%")
    sum_col4.metric("Avg Anomaly", f"{df['anomaly_score'].mean()*100:.1f}%" if "anomaly_score" in df.columns else "N/A")

    # Threat type breakdown
    if "attack_type" in df.columns:
        st.markdown("### Threat Type Breakdown")
        type_counts = df["attack_type"].value_counts()
        fig = go.Figure(go.Bar(
            x=type_counts.values,
            y=type_counts.index,
            orientation="h",
            marker_color=["#ef4444" if t != "Normal" else "#06b6d4" for t in type_counts.index],
        ))
        fig.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font={"color": "#94a3b8", "size": 11},
            height=300,
            margin=dict(l=100, r=20, t=20, b=30),
        )
        st.plotly_chart(fig, use_container_width=True)

    # Top malicious IPs
    if "source_ip" in threats.columns and len(threats) > 0:
        st.markdown("### Top Malicious Source IPs")
        top_ips = threats["source_ip"].value_counts().head(10).reset_index()
        top_ips.columns = ["Source IP", "Threat Count"]
        st.dataframe(top_ips, use_container_width=True, height=350)
