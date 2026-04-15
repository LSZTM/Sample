import streamlit as st
#═════════════════════════════════════════════════════════════════════════════
#  DESIGN SYSTEM
#  ECGVault Edition — Obsidian base · Emerald accent · Crimson danger
#  Typography: Syne (display) · DM Mono (labels/code) · DM Sans (body)
# ═════════════════════════════════════════════════════════════════════════════

def load_css() -> None:
    st.markdown("""
    <link href="https://fonts.googleapis.com/css2?family=Syne:wght@400;600;700;800&family=DM+Mono:ital,wght@0,300;0,400;0,500;1,300&family=DM+Sans:ital,opsz,wght@0,9..40,300;0,9..40,400;0,9..40,500;1,9..40,300&display=swap" rel="stylesheet">

    <style>
    /* ── DESIGN TOKENS ─────────────────────────────────────────────── */
    :root {
        /* Surfaces */
        --bg-base:        #07090f;
        --bg-raised:      #0b0e18;
        --bg-elevated:    #0f1220;
        --bg-overlay:     #141828;
        --bg-hover:       #181d30;

        /* Borders */
        --border-subtle:  #151a28;
        --border-default: #1c2238;
        --border-accent:  #1e3040;

        /* Text */
        --text-primary:   #e8edf8;
        --text-secondary: #7d879e;
        --text-muted:     #3d4560;
        --text-disabled:  #252d42;

        /* Accent — emerald teal (medical / biometric feel) */
        --accent:         #00c896;
        --accent-bright:  #00ffbb;
        --accent-dim:     rgba(0, 200, 150, 0.12);
        --accent-glow:    rgba(0, 200, 150, 0.06);
        --accent-border:  rgba(0, 200, 150, 0.25);

        /* Semantic */
        --success:        #00c896;
        --success-dim:    rgba(0, 200, 150, 0.10);
        --warning:        #f0a040;
        --warning-dim:    rgba(240, 160, 64, 0.10);
        --danger:         #e03060;
        --danger-dim:     rgba(224, 48, 96, 0.10);
        --info:           #4488ff;
        --info-dim:       rgba(68, 136, 255, 0.10);

        /* Fonts */
        --font-display:   'Syne', sans-serif;
        --font-body:      'DM Sans', sans-serif;
        --font-mono:      'DM Mono', monospace;

        /* Radii */
        --radius-sm:      4px;
        --radius-md:      8px;
        --radius-lg:      12px;

        /* Shadows */
        --shadow-sm:      0 1px 4px rgba(0,0,0,0.6);
        --shadow-md:      0 4px 20px rgba(0,0,0,0.5);
        --shadow-lg:      0 8px 40px rgba(0,0,0,0.6);
    }

    /* ── BASE ──────────────────────────────────────────────────────── */
    html, body, [class*="css"] { font-family: var(--font-body); }

    .stApp {
        background-color: var(--bg-base) !important;
        color: var(--text-secondary);
    }

    /* Hide hamburger / footer / header */
    #MainMenu, footer { visibility: hidden; }

    /* Scrollbar */
    ::-webkit-scrollbar       { width: 4px; height: 4px; }
    ::-webkit-scrollbar-track { background: var(--bg-base); }
    ::-webkit-scrollbar-thumb { background: var(--border-default); border-radius: 99px; }
    ::-webkit-scrollbar-thumb:hover { background: var(--border-accent); }

    /* ── SIDEBAR ───────────────────────────────────────────────────── */
    /* SIDEBAR BASE */
    [data-testid="stSidebar"] {
        background-color: var(--bg-raised) !important;
        border-right: 1px solid var(--border-subtle) !important;
    }

    /* ONLY apply width when expanded */
    [data-testid="stSidebar"][aria-expanded="true"] {
        min-width: 320px !important;
        flex-basis: 320px !important;
    }

    /* fully collapse when closed */
    [data-testid="stSidebar"][aria-expanded="false"] {
        min-width: 0 !important;
        flex-basis: 0 !important;
    }
    [data-testid="stSidebar"] .block-container { padding: 0 !important; }

    /* Brand block */
    .ev-brand {
        padding: 28px 20px 20px;
        border-bottom: 1px solid var(--border-subtle);
        margin-bottom: 4px;
    }
    .ev-brand-name {
        font-family: var(--font-display);
        font-weight: 800;
        font-size: 1.15rem;
        color: var(--text-primary);
        letter-spacing: -0.02em;
    }
    .ev-brand-name span { color: var(--accent); }
    .ev-brand-tag {
        font-family: var(--font-mono);
        font-size: 0.58rem;
        letter-spacing: 0.2em;
        text-transform: uppercase;
        color: var(--text-muted);
        margin-top: 4px;
    }

    /* Sidebar nav label */
    .ev-nav-label {
        font-family: var(--font-mono);
        font-size: 0.58rem;
        letter-spacing: 0.2em;
        text-transform: uppercase;
        color: var(--text-disabled);
        padding: 18px 20px 6px;
    }

    /* Vault status indicator */
    .ev-vault-status {
        display: flex;
        align-items: center;
        gap: 10px;
        margin: 8px 14px;
        padding: 11px 14px;
        border-radius: var(--radius-md);
        border: 1px solid;
        font-family: var(--font-mono);
        font-size: 0.7rem;
        letter-spacing: 0.04em;
    }
    .ev-vault-status.locked {
        background: rgba(224,48,96,0.05);
        border-color: rgba(224,48,96,0.18);
        color: #904060;
    }
    .ev-vault-status.sealed {
        background: rgba(240,160,64,0.05);
        border-color: rgba(240,160,64,0.18);
        color: #907040;
    }
    .ev-vault-status.open {
        background: rgba(0,200,150,0.05);
        border-color: rgba(0,200,150,0.18);
        color: var(--accent);
    }
    .ev-vault-dot {
        width: 7px; height: 7px;
        border-radius: 50%; flex-shrink: 0;
    }
    .ev-vault-status.locked  .ev-vault-dot { background: var(--danger); }
    .ev-vault-status.sealed  .ev-vault-dot { background: var(--warning); }
    .ev-vault-status.open    .ev-vault-dot {
        background: var(--accent);
        box-shadow: 0 0 8px rgba(0,200,150,0.7);
        animation: pulse-dot 2.5s ease-in-out infinite;
    }
    @keyframes pulse-dot {
        0%, 100% { opacity: 1; }
        50%       { opacity: 0.3; }
    }

    /* Step progress in sidebar */
    .ev-step-item {
        display: flex;
        align-items: center;
        gap: 12px;
        padding: 9px 20px;
        font-family: var(--font-body);
        font-size: 0.8rem;
        color: var(--text-muted);
        transition: color 0.2s;
    }
    .ev-step-item.active { color: var(--text-primary); }
    .ev-step-item.done   { color: var(--accent); }

    .ev-step-num {
        width: 24px; height: 24px;
        border-radius: 50%;
        border: 1px solid var(--border-default);
        display: flex; align-items: center; justify-content: center;
        font-family: var(--font-mono);
        font-size: 0.65rem;
        color: var(--text-muted);
        flex-shrink: 0;
        transition: all 0.25s;
    }
    .ev-step-item.active .ev-step-num {
        border-color: var(--accent);
        color: var(--accent);
        box-shadow: 0 0 10px rgba(0,200,150,0.3);
    }
    .ev-step-item.done .ev-step-num {
        background: var(--accent);
        border-color: var(--accent);
        color: #000;
        font-weight: 700;
    }

    /* Sidebar param group */
    .ev-param-group {
        margin: 6px 14px;
        padding: 14px;
        background: var(--bg-elevated);
        border: 1px solid var(--border-subtle);
        border-radius: var(--radius-md);
    }
    .ev-param-label {
        font-family: var(--font-mono);
        font-size: 0.58rem;
        letter-spacing: 0.18em;
        text-transform: uppercase;
        color: var(--text-muted);
        margin-bottom: 10px;
    }

    /* ── MAIN CONTENT ──────────────────────────────────────────────── */
    .main .block-container {
        padding: 36px 40px 60px !important;
        max-width: 1100px !important;
    }

    /* ── PAGE HEADER ───────────────────────────────────────────────── */
    .ev-page-header {
        margin-bottom: 32px;
        padding-bottom: 24px;
        border-bottom: 1px solid var(--border-subtle);
    }
    .ev-eyebrow {
        font-family: var(--font-mono);
        font-size: 0.62rem;
        letter-spacing: 0.22em;
        text-transform: uppercase;
        color: var(--accent);
        margin-bottom: 6px;
    }
    .ev-page-title {
        font-family: var(--font-display);
        font-size: 1.7rem;
        font-weight: 700;
        color: var(--text-primary);
        letter-spacing: -0.025em;
        line-height: 1.15;
        margin: 0;
    }
    .ev-page-desc {
        font-family: var(--font-mono);
        font-size: 0.75rem;
        color: var(--text-muted);
        margin-top: 8px;
        letter-spacing: 0.02em;
        line-height: 1.6;
    }

    /* ── STEP CARD ─────────────────────────────────────────────────── */
    .ev-step-card {
        background: var(--bg-raised);
        border: 1px solid var(--border-subtle);
        border-radius: var(--radius-lg);
        margin-bottom: 20px;
        overflow: hidden;
        position: relative;
        transition: border-color 0.25s, box-shadow 0.25s;
    }
    .ev-step-card.active {
        border-color: var(--accent-border);
        box-shadow: 0 0 0 1px var(--accent-border), var(--shadow-md);
    }
    .ev-step-card.done {
        border-color: rgba(0,200,150,0.12);
    }
    /* top accent line */
    .ev-step-card::before {
        content: '';
        position: absolute;
        top: 0; left: 0; right: 0;
        height: 2px;
        background: transparent;
        transition: background 0.3s;
    }
    .ev-step-card.active::before { background: var(--accent); }
    .ev-step-card.done::before   { background: rgba(0,200,150,0.3); }

    .ev-step-card-header {
        display: flex;
        align-items: center;
        gap: 16px;
        padding: 20px 24px 16px;
        border-bottom: 1px solid var(--border-subtle);
    }
    .ev-step-card-num {
        font-family: var(--font-display);
        font-size: 2rem;
        font-weight: 800;
        color: var(--text-disabled);
        line-height: 1;
        min-width: 36px;
        transition: color 0.25s;
    }
    .ev-step-card.active .ev-step-card-num { color: var(--accent); }
    .ev-step-card.done   .ev-step-card-num { color: rgba(0,200,150,0.35); }

    .ev-step-card-title {
        font-family: var(--font-display);
        font-size: 1.0rem;
        font-weight: 700;
        color: var(--text-primary);
        letter-spacing: -0.01em;
        line-height: 1.2;
    }
    .ev-step-card-subtitle {
        font-family: var(--font-mono);
        font-size: 0.65rem;
        letter-spacing: 0.12em;
        color: var(--text-muted);
        margin-top: 3px;
        text-transform: uppercase;
    }
    .ev-step-card-body { padding: 24px; }

    /* ── SECTION LABEL ─────────────────────────────────────────────── */
    .ev-section-label {
        font-family: var(--font-mono);
        font-size: 0.6rem;
        letter-spacing: 0.2em;
        text-transform: uppercase;
        color: var(--text-muted);
        margin-bottom: 12px;
        display: flex;
        align-items: center;
        gap: 10px;
    }
    .ev-section-label::after {
        content: '';
        flex: 1; height: 1px;
        background: var(--border-subtle);
    }

    /* ── BADGES ────────────────────────────────────────────────────── */
    .ev-badge {
        display: inline-flex;
        align-items: center;
        gap: 5px;
        padding: 3px 10px;
        border-radius: var(--radius-sm);
        font-family: var(--font-mono);
        font-size: 0.65rem;
        font-weight: 500;
        letter-spacing: 0.08em;
        border: 1px solid;
        text-transform: uppercase;
    }
    .ev-badge.success { background: var(--success-dim); border-color: rgba(0,200,150,0.28); color: var(--accent); }
    .ev-badge.danger  { background: var(--danger-dim);  border-color: rgba(224,48,96,0.28); color: var(--danger); }
    .ev-badge.warning { background: var(--warning-dim); border-color: rgba(240,160,64,0.28);color: var(--warning);}
    .ev-badge.info    { background: var(--info-dim);    border-color: rgba(68,136,255,0.28); color: var(--info);   }
    .ev-badge.neutral { background: var(--bg-elevated); border-color: var(--border-default); color: var(--text-secondary); }

    /* ── METRIC CARD ───────────────────────────────────────────────── */
    .ev-metric {
        background: var(--bg-elevated);
        border: 1px solid var(--border-subtle);
        border-radius: var(--radius-md);
        padding: 18px 20px;
        position: relative;
        overflow: hidden;
    }
    .ev-metric::before {
        content: '';
        position: absolute;
        top: 0; left: 0; right: 0; height: 2px;
    }
    .ev-metric.success::before { background: var(--success); }
    .ev-metric.danger::before  { background: var(--danger);  }
    .ev-metric.info::before    { background: var(--info);    }
    .ev-metric.neutral::before { background: var(--border-default); }

    .ev-metric-label {
        font-family: var(--font-mono);
        font-size: 0.58rem;
        letter-spacing: 0.18em;
        text-transform: uppercase;
        color: var(--text-muted);
        margin-bottom: 8px;
    }
    .ev-metric-value {
        font-family: var(--font-display);
        font-size: 1.6rem;
        font-weight: 700;
        color: var(--text-primary);
        letter-spacing: -0.02em;
        line-height: 1;
    }
    .ev-metric.success .ev-metric-value { color: var(--accent);   }
    .ev-metric.danger  .ev-metric-value { color: var(--danger);   }
    .ev-metric.info    .ev-metric-value { color: var(--info);     }
    .ev-metric-sub {
        font-family: var(--font-mono);
        font-size: 0.62rem;
        color: var(--text-muted);
        margin-top: 5px;
    }

    /* ── CHALLENGE CARD ────────────────────────────────────────────── */
    .ev-challenge {
        background: var(--bg-elevated);
        border: 1px solid var(--border-subtle);
        border-radius: var(--radius-md);
        padding: 20px;
        height: 100%;
        position: relative;
        overflow: hidden;
    }
    .ev-challenge::before {
        content: '';
        position: absolute;
        top: 0; left: 0; right: 0; height: 2px;
    }
    .ev-challenge.success::before { background: var(--success); }
    .ev-challenge.danger::before  { background: var(--danger);  }

    .ev-challenge-num {
        font-family: var(--font-mono);
        font-size: 0.58rem;
        letter-spacing: 0.2em;
        text-transform: uppercase;
        color: var(--text-muted);
        margin-bottom: 6px;
    }
    .ev-challenge-title {
        font-family: var(--font-display);
        font-size: 0.9rem;
        font-weight: 700;
        color: var(--text-primary);
        margin-bottom: 3px;
        letter-spacing: -0.01em;
    }
    .ev-challenge-sub {
        font-family: var(--font-mono);
        font-size: 0.62rem;
        color: var(--text-muted);
        margin-bottom: 14px;
    }

    /* ── CODE BLOCK ────────────────────────────────────────────────── */
    .ev-code {
        background: var(--bg-base);
        border: 1px solid var(--border-subtle);
        border-radius: var(--radius-md);
        padding: 14px 16px;
        font-family: var(--font-mono);
        font-size: 0.72rem;
        color: var(--text-secondary);
        line-height: 1.8;
        word-break: break-all;
        margin-top: 10px;
    }
    .ev-code .k { color: var(--text-muted); }      /* key   */
    .ev-code .v { color: var(--accent); }           /* value */
    .ev-code .e { color: var(--danger); }           /* error */
    .ev-code .ok{ color: var(--success); }          /* ok    */

    /* ── VAULT BOX ─────────────────────────────────────────────────── */
    .ev-vault-box {
        background: var(--bg-base);
        border: 1px solid var(--border-default);
        border-radius: var(--radius-md);
        padding: 16px;
        position: relative;
        overflow: hidden;
    }
    .ev-vault-box::after {
        content: 'ENCRYPTED';
        position: absolute;
        top: 10px; right: 14px;
        font-family: var(--font-mono);
        font-size: 0.55rem;
        letter-spacing: 0.2em;
        color: var(--text-disabled);
    }
    .ev-vault-ct {
        font-family: var(--font-mono);
        font-size: 0.7rem;
        color: var(--text-muted);
        word-break: break-all;
        line-height: 1.7;
        opacity: 0.7;
    }

    /* ── PIPELINE CONNECTOR ────────────────────────────────────────── */
    .ev-pipeline {
        display: flex;
        align-items: center;
        gap: 0;
        margin: 16px 0;
        flex-wrap: wrap;
    }
    .ev-pipeline-step {
        background: var(--bg-elevated);
        border: 1px solid var(--border-default);
        border-radius: var(--radius-sm);
        padding: 6px 12px;
        font-family: var(--font-mono);
        font-size: 0.65rem;
        color: var(--text-secondary);
        white-space: nowrap;
    }
    .ev-pipeline-arrow {
        font-size: 0.7rem;
        color: var(--accent);
        padding: 0 6px;
        opacity: 0.6;
    }

    /* ── STREAMLIT COMPONENT OVERRIDES ────────────────────────────── */

    /* Buttons */
    .stButton > button {
        font-family: var(--font-body) !important;
        font-size: 0.82rem !important;
        font-weight: 500 !important;
        letter-spacing: 0.01em !important;
        padding: 9px 20px !important;
        border-radius: var(--radius-md) !important;
        border: 1px solid var(--border-default) !important;
        background: var(--bg-elevated) !important;
        color: var(--text-secondary) !important;
        transition: all 0.15s ease !important;
        box-shadow: none !important;
    }
    .stButton > button:hover {
        background: var(--bg-hover) !important;
        border-color: var(--border-accent) !important;
        color: var(--text-primary) !important;
    }
    .stButton > button[kind="primary"] {
        background: var(--accent) !important;
        border-color: var(--accent) !important;
        color: #000 !important;
        font-weight: 600 !important;
    }
    .stButton > button[kind="primary"]:hover {
        background: var(--accent-bright) !important;
        border-color: var(--accent-bright) !important;
        box-shadow: 0 0 20px rgba(0,200,150,0.25) !important;
    }

    /* Inputs */
    .stTextInput > div > div > input,
    .stNumberInput > div > div > input,
    .stTextArea > div > div > textarea {
        background: var(--bg-base) !important;
        border: 1px solid var(--border-default) !important;
        border-radius: var(--radius-md) !important;
        color: var(--text-primary) !important;
        font-family: var(--font-body) !important;
        font-size: 0.85rem !important;
        padding: 10px 14px !important;
    }
    .stTextInput > div > div > input:focus,
    .stTextArea > div > div > textarea:focus {
        border-color: var(--accent) !important;
        box-shadow: 0 0 0 3px var(--accent-dim) !important;
    }
    input[type="password"] {
        font-family: var(--font-mono) !important;
        letter-spacing: 0.18em !important;
    }

    /* Labels */
    .stTextInput label, .stTextArea label,
    .stSelectbox label, .stSlider label,
    .stCheckbox label, .stToggle label {
        font-family: var(--font-mono) !important;
        font-size: 0.62rem !important;
        letter-spacing: 0.16em !important;
        text-transform: uppercase !important;
        color: var(--text-muted) !important;
    }

    /* Selectbox */
    .stSelectbox > div > div {
        background: var(--bg-base) !important;
        border: 1px solid var(--border-default) !important;
        border-radius: var(--radius-md) !important;
        color: var(--text-primary) !important;
    }
    div[data-baseweb="select"] span { color: var(--text-primary) !important; }
    div[data-baseweb="select"] svg  { fill: var(--text-muted) !important; }
    ul[data-baseweb="menu"] {
        background: var(--bg-elevated) !important;
        border: 1px solid var(--border-default) !important;
        border-radius: var(--radius-md) !important;
    }
    li[role="option"] { color: var(--text-secondary) !important; font-size: 0.84rem !important; }
    li[role="option"]:hover,
    li[role="option"][aria-selected="true"] {
        background: var(--accent-dim) !important;
        color: var(--text-primary) !important;
    }

    /* Slider */
    .stSlider [data-baseweb="slider"] [role="slider"] {
        background: var(--accent) !important;
        border-color: var(--accent) !important;
    }
    .stSlider [data-baseweb="slider"] > div:first-child { background: var(--border-default) !important; }
    .stSlider [data-baseweb="slider"] [role="progressbar"] { background: var(--accent) !important; }

    /* Toggle */
    .stToggle [data-baseweb="checkbox"] + div { background: var(--border-default) !important; }
    [data-testid="stToggleSwitch"][aria-checked="true"] { background: var(--accent) !important; }

    /* Progress */
    .stProgress > div > div > div {
        background: var(--accent) !important;
        border-radius: 999px !important;
    }

    /* Metrics */
    .stMetric {
        background: var(--bg-elevated) !important;
        border: 1px solid var(--border-subtle) !important;
        border-radius: var(--radius-md) !important;
        padding: 18px 20px !important;
    }
    .stMetric label {
        font-family: var(--font-mono) !important;
        font-size: 0.58rem !important;
        color: var(--text-muted) !important;
        text-transform: uppercase !important;
        letter-spacing: 0.16em !important;
    }
    .stMetric [data-testid="stMetricValue"] {
        font-family: var(--font-display) !important;
        font-size: 1.6rem !important;
        font-weight: 700 !important;
        color: var(--text-primary) !important;
    }

    /* Expander */
    .streamlit-expanderHeader {
        background: var(--bg-elevated) !important;
        border: 1px solid var(--border-subtle) !important;
        border-radius: var(--radius-md) !important;
        color: var(--text-secondary) !important;
        font-family: var(--font-body) !important;
        font-size: 0.82rem !important;
        font-weight: 500 !important;
    }
    .streamlit-expanderContent {
        background: var(--bg-base) !important;
        border: 1px solid var(--border-subtle) !important;
        border-top: none !important;
    }

    /* Alerts */
    .stAlert {
        border-radius: var(--radius-md) !important;
        font-family: var(--font-body) !important;
        font-size: 0.82rem !important;
    }

    /* Divider */
    hr { border-color: var(--border-subtle) !important; margin: 24px 0 !important; }

    /* JSON viewer */
    [data-testid="stJson"] {
        background: var(--bg-base) !important;
        border: 1px solid var(--border-subtle) !important;
        border-radius: var(--radius-md) !important;
    }

    /* Tabs */
    .stTabs [data-baseweb="tab-list"] {
        background: transparent !important;
        border-bottom: 1px solid var(--border-subtle) !important;
        gap: 0 !important;
    }
    .stTabs [data-baseweb="tab"] {
        font-family: var(--font-body) !important;
        font-size: 0.82rem !important;
        color: var(--text-muted) !important;
        background: transparent !important;
        border: none !important;
        padding: 10px 18px !important;
    }
    .stTabs [aria-selected="true"] {
        color: var(--text-primary) !important;
        border-bottom: 2px solid var(--accent) !important;
        background: transparent !important;
    }

    /* Code */
    code {
        font-family: var(--font-mono) !important;
        font-size: 0.78rem !important;
        background: var(--bg-elevated) !important;
        color: var(--accent) !important;
        padding: 1px 6px !important;
        border-radius: 3px !important;
    }
    pre { background: var(--bg-base) !important; border-radius: var(--radius-md) !important; }
    pre code { background: transparent !important; color: var(--text-secondary) !important; }

    /* Caption */
    .stCaption, [data-testid="stCaptionContainer"] {
        font-family: var(--font-mono) !important;
        font-size: 0.65rem !important;
        color: var(--text-muted) !important;
        letter-spacing: 0.04em !important;
    }
    </style>
    """, unsafe_allow_html=True)
