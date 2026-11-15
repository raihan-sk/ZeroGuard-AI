
from __future__ import annotations

from pathlib import Path
import hashlib
import sys

import altair as alt
import joblib
import numpy as np
import pandas as pd
import streamlit as st

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from zeroguard_engine import recommend_threshold, score_flows

MODEL_FILE = ROOT / "models" / "zeroguard_deploy.joblib"
MAX_FILE_MB = 25
MAX_ROWS = 10_000
PALETTE = {
    "aqua": "#22D3EE",
    "teal": "#2DD4BF",
    "red": "#FB7185",
    "gold": "#FBBF24",
    "muted": "#9AA9BF",
}

st.set_page_config(
    page_title="ZeroGuard AI · Threat Console",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
<style>
:root { color-scheme: dark; }
.block-container { padding-top: 1.6rem; padding-bottom: 2.8rem; max-width: 1390px; }
[data-testid="stAppViewContainer"] { background: #080F1D; }
[data-testid="stSidebar"] { background: #101C2D; border-right: 1px solid #233248; }
[data-testid="stHeader"] { background: transparent; }
h1,h2,h3 {letter-spacing: -.028em;}
h1 {font-size: 2.5rem !important; font-weight: 800 !important;}
h2 {font-size: 1.55rem !important;}
[data-testid="stMetric"] { background: #111F32; border: 1px solid #263A53; border-radius: 14px; padding: 18px 17px; }
[data-testid="stMetricValue"] { font-size: 1.85rem; font-weight: 750; letter-spacing: -.03em; }
[data-testid="stMetricLabel"] { color: #A9B7CC; }
[data-testid="stFileUploader"] {border: 1px dashed #365271; border-radius: 15px; padding: 8px; background: #101B2D;}
[data-testid="stTabs"] button { font-weight: 650; }
[data-testid="stAlert"] { border-radius: 12px; }
div[data-testid="stDataFrame"] {border: 1px solid #233248; border-radius: 10px; overflow: hidden;}
.zg-eyebrow { text-transform: uppercase; letter-spacing: .18em; color: #2DD4BF; font-size: .76rem; font-weight: 800; margin-bottom: .35rem; }
.zg-lead {color:#A9B7CC; font-size:1.02rem; margin-top:-.5rem; margin-bottom:1.3rem;}
.zg-panel {background:#101C2D; border:1px solid #263A53; border-radius:15px; padding:18px 22px; margin:.45rem 0 1.05rem;}
.zg-step {font-size:.79rem; text-transform:uppercase; letter-spacing:.1em; color:#2DD4BF; font-weight:750;}
.zg-card-title {font-size:1.03rem; font-weight:750; margin:.2rem 0; color:#E8F2FF;}
.zg-card-text {font-size:.89rem; color:#9CAEC5; margin-bottom:.12rem;}
.zg-label {font-size:.77rem; letter-spacing:.10em; font-weight:800; color:#84A0C2; text-transform:uppercase;}
.zg-status {display:inline-block; padding:.25rem .65rem; border:1px solid #226B65; border-radius:99px; color:#70E9CB; background:#10312F; font-size:.75rem; font-weight:800; letter-spacing:.04em;}
.zg-small {font-size:.78rem; color:#91A2BB;}
hr {border-color:#27364B !important;}
</style>
""",
    unsafe_allow_html=True,
)


@st.cache_resource(show_spinner="Loading detection engine...")
def load_bundle() -> dict:
    # Never deserialize an untrusted joblib/pickle file.
    return joblib.load(MODEL_FILE)


def read_flow_csv(uploaded) -> pd.DataFrame:
    if uploaded.size > MAX_FILE_MB * 1024 * 1024:
        raise ValueError(f"CSV exceeds the {MAX_FILE_MB} MB limit. Upload a smaller extract.")
    uploaded.seek(0)
    data = pd.read_csv(uploaded, nrows=MAX_ROWS + 1, low_memory=False)
    if data.empty:
        raise ValueError("This CSV has no data rows.")
    if len(data) > MAX_ROWS:
        st.warning(f"Only the first {MAX_ROWS:,} rows were loaded. The summary is not representative of the entire file.")
        data = data.iloc[:MAX_ROWS].copy()
    return data


def safe_export_csv(frame: pd.DataFrame) -> bytes:
    """Avoid spreadsheet formula execution when analysts open downloaded CSVs."""
    safe = frame.copy()
    for name in safe.select_dtypes(include=["object", "string"]).columns:
        safe[name] = safe[name].map(
            lambda value: "'" + value if isinstance(value, str)
            and value.lstrip().startswith(("=", "+", "-", "@", "\t", "\r")) else value
        )
    return safe.to_csv(index=False).encode("utf-8")


def score_histogram(scores: np.ndarray, threshold: float):
    score_frame = pd.DataFrame({"Score": scores})
    chart = (
        alt.Chart(score_frame)
        .mark_bar(color=PALETTE["aqua"], opacity=0.86, cornerRadiusTopLeft=3, cornerRadiusTopRight=3)
        .encode(
            x=alt.X("Score:Q", bin=alt.Bin(maxbins=35), title="Detection score"),
            y=alt.Y("count():Q", title="Number of flows"),
            tooltip=[alt.Tooltip("count():Q", title="Flows")],
        )
    )
    rule = alt.Chart(pd.DataFrame({"Threshold": [threshold]})).mark_rule(
        color=PALETTE["red"], strokeDash=[5, 4], strokeWidth=2.5
    ).encode(x="Threshold:Q")
    return (chart + rule).properties(height=300)


def protocol_chart(frame: pd.DataFrame, flagged: np.ndarray):
    if "proto" not in frame:
        return None
    analysis = pd.DataFrame({
        "Protocol": frame["proto"].astype("string").fillna("Unknown"),
        "Status": np.where(flagged, "Investigate", "No alert"),
    })
    top = analysis["Protocol"].value_counts().head(9).index
    counts = analysis[analysis["Protocol"].isin(top)].groupby(
        ["Protocol", "Status"], observed=True
    ).size().reset_index(name="Flows")
    return alt.Chart(counts).mark_bar().encode(
        x=alt.X("Protocol:N", sort="-y", title="Protocol"),
        y=alt.Y("Flows:Q", title="Flows"),
        color=alt.Color(
            "Status:N",
            scale=alt.Scale(domain=["No alert", "Investigate"], range=[PALETTE["teal"], PALETTE["red"]]),
        ),
        tooltip=["Protocol:N", "Status:N", "Flows:Q"],
    ).properties(height=285)


def file_order_chart(flagged: np.ndarray):
    n = len(flagged)
    batch_size = max(50, int(np.ceil(n / 50)))
    batch_id = np.arange(n) // batch_size
    rolling = pd.DataFrame({"Batch": batch_id + 1, "Alert": flagged.astype(float)})
    grouped = rolling.groupby("Batch", as_index=False)["Alert"].mean()
    grouped["Alert rate (%)"] = grouped["Alert"] * 100
    return alt.Chart(grouped).mark_line(
        color=PALETTE["gold"], strokeWidth=2.8, point=True
    ).encode(
        x=alt.X("Batch:Q", title="Sequential file batch"),
        y=alt.Y("Alert rate (%):Q", title="Alert rate (%)", scale=alt.Scale(zero=True)),
        tooltip=["Batch:Q", alt.Tooltip("Alert rate (%):Q", format=".2f")],
    ).properties(height=270)


st.markdown('<div class="zg-eyebrow">SECURITY ANALYTICS / NETWORK FLOWS</div>', unsafe_allow_html=True)
st.title("🛡️ ZeroGuard AI")
st.markdown(
    '<div class="zg-lead">Threat Detection Console — intelligent scoring, alert investigation and controlled adaptation.</div>',
    unsafe_allow_html=True,
)

if not MODEL_FILE.is_file():
    st.error("Detection model missing: `models/zeroguard_deploy.joblib`.")
    st.code("python src/build_deploy_model.py", language="bash")
    st.stop()

try:
    bundle = load_bundle()
except Exception as exc:
    st.error(f"Unable to load the local model bundle: {exc}")
    st.stop()

frozen = float(bundle["frozen_threshold"])
withheld_family = bundle.get("withheld_family_for_demo", "Unavailable")

with st.sidebar:
    st.markdown("### 🛡️ ZeroGuard AI")
    st.markdown('<span class="zg-status">● ENGINE READY</span>', unsafe_allow_html=True)
    st.caption("CSV batch analysis · no live capture")
    st.divider()
    st.markdown('<div class="zg-label">Detection configuration</div>', unsafe_allow_html=True)
    st.metric("Decision threshold", f"{frozen:.4f}")
    st.metric("Input features", str(len(bundle["features"])))
    st.write("**Model:** LightGBM flow detector")
    st.write("**Processing mode:** Local file upload")
    st.divider()
    st.caption(f"Upload limit: {MAX_FILE_MB} MB · First {MAX_ROWS:,} records")
    with st.expander("Model details"):
        st.write("Version:", bundle.get("version", "Unknown"))
        st.write("Training benchmark:", "UNSW-NB15")
        st.write("Evaluation holdout:", withheld_family)
        st.write("The holdout name is metadata, not an output predicted by the model.")

analysis_tab, adapt_tab, info_tab = st.tabs(
    ["◈ Traffic Explorer", "⚙ Adaptive Alerts", "ⓘ System Details"]
)

recommendation = {
    "accepted": False, "threshold": frozen, "reason": "No independently verified benign batch",
    "ks": None, "trusted_gain_pp": 0.0, "guard_known_loss_pp": 0.0,
}

with adapt_tab:
    st.subheader("Adaptive Alert Review")
    st.markdown(
        "Explore threshold adjustments using **independently verified benign traffic**. "
        "Any approved adjustment applies only to an optional preview; it is not saved or applied to future uploads."
    )
    with st.expander("What qualifies as verified traffic?"):
        st.write(
            "Use separate data confirmed benign by an analyst or trusted process. "
            "Do not use this model's own unflagged flows or the official benchmark test partition "
            "to authorize adaptation."
        )
    verified_upload = st.file_uploader("Verified benign flow file · CSV", type=["csv"], key="verified")
    confirmed = st.checkbox("These flows were verified independently, not selected using ZeroGuard predictions.")
    if verified_upload is not None:
        if not confirmed:
            st.info("Confirm the verification source to enable the threshold review.")
        else:
            try:
                verified_df = read_flow_csv(verified_upload)
                if "label" in verified_df:
                    labels = pd.to_numeric(verified_df["label"], errors="coerce")
                    if not labels.eq(0).all():
                        raise ValueError("The verified data contains a non-benign or invalid label.")
                recommendation = recommend_threshold(verified_df, bundle)
                m1, m2, m3 = st.columns(3)
                m1.metric("Suggested threshold", f"{recommendation['threshold']:.5f}")
                m2.metric("Estimated alert reduction", f"{recommendation['trusted_gain_pp']:.2f} pp")
                m3.metric("Known-attack recall loss", f"{recommendation['guard_known_loss_pp']:.2f} pp")
                st.caption("Gain and loss are estimated on separate development reference and guard data; they are not production guarantees.")
                if recommendation["ks"] is not None:
                    st.write(f"**Distribution-shift statistic:** {recommendation['ks']:.4f}")
                if recommendation["accepted"]:
                    st.success("Candidate passed the configured guard. Preview is available in Traffic Explorer.")
                else:
                    st.warning(recommendation["reason"])
            except Exception as exc:
                st.error(f"Unable to analyze verified batch: {exc}")

with analysis_tab:
    st.subheader("Network Traffic Analysis")
    st.write("Upload a prepared UNSW-NB15-style CSV file to investigate anomalous and attack-like network flows.")
    with st.expander("CSV format and required features", expanded=False):
        st.write(
            "Use a prepared UNSW-NB15-style flow CSV. The model expects all "
            f"{len(bundle['features'])} trained feature columns. The `label` and "
            "`attack_cat` columns are optional and are used only for labeled evaluation."
        )
        st.code(", ".join(bundle["features"]), language=None)
        st.download_button(
            "Download CSV column template",
            data=pd.DataFrame(columns=bundle["features"]).to_csv(index=False).encode("utf-8"),
            file_name="zeroguard_flow_template.csv",
            mime="text/csv",
            help="Header-only template; add real flow values before uploading.",
            key="csv_column_template",
        )
    uploaded = st.file_uploader("Network-flow CSV", type=["csv"], key="flows")

    if uploaded is None:
        st.markdown(
            '<div class="zg-panel"><div class="zg-label">Ready for analysis</div>'
            '<div class="zg-card-title">Drop in a network-flow file to begin</div>'
            '<div class="zg-card-text">Your score distribution, threat indicators and investigative table appear here after scoring.</div>'
            '</div>', unsafe_allow_html=True,
        )
        p1, p2, p3 = st.columns(3)
        with p1:
            st.markdown('<div class="zg-panel"><div class="zg-step">01 · Ingest</div><div class="zg-card-title">Upload flows</div><div class="zg-card-text">Use a CSV with the trained feature columns.</div></div>', unsafe_allow_html=True)
        with p2:
            st.markdown('<div class="zg-panel"><div class="zg-step">02 · Inspect</div><div class="zg-card-title">Review alerts</div><div class="zg-card-text">Explore detection scores, protocols and flagged records.</div></div>', unsafe_allow_html=True)
        with p3:
            st.markdown('<div class="zg-panel"><div class="zg-step">03 · Export</div><div class="zg-card-title">Share findings</div><div class="zg-card-text">Download an annotated CSV for further analysis.</div></div>', unsafe_allow_html=True)
    else:
        try:
            if verified_upload is not None and hashlib.sha256(uploaded.getvalue()).digest() == hashlib.sha256(verified_upload.getvalue()).digest():
                raise ValueError("Do not use the same CSV for traffic evaluation and adaptation review.")
            df = read_flow_csv(uploaded)
            missing_features = [feature for feature in bundle["features"] if feature not in df.columns]
            if missing_features:
                raise ValueError(
                    f"This CSV is missing {len(missing_features)} required model feature(s): "
                    + ", ".join(missing_features)
                    + ". Download the column template above for the expected names."
                )
            use_suggested = st.checkbox(
                "Preview accepted adaptive threshold",
                disabled=not recommendation["accepted"],
                help="The default threshold is frozen unless you explicitly enable this preview.",
            )
            threshold = float(recommendation["threshold"]) if use_suggested and recommendation["accepted"] else frozen
            with st.spinner("Scoring uploaded network flows..."):
                scores = score_flows(df, bundle)
            flagged = scores > threshold
            st.caption("Detection scores indicate model-derived attack suspicion; they are not proof of a cyberattack.")
            m1, m2, m3, m4 = st.columns(4)
            m1.metric("Flows analyzed", f"{len(df):,}")
            m2.metric("Needs investigation", f"{int(flagged.sum()):,}")
            m3.metric("Flagged share", f"{100 * flagged.mean():.2f}%")
            m4.metric("Active threshold", f"{threshold:.4f}")
            st.caption("Flagged share is not the false-positive rate. FPR requires independently labeled benign traffic.")

            st.markdown("### Detection Overview")
            a, b = st.columns([1.6, 1.0], gap="large")
            with a:
                st.markdown("**Detection score distribution**")
                st.altair_chart(score_histogram(scores, threshold), use_container_width=True)
                st.caption("Red dashed line = decision threshold. Higher scores are more likely to be flagged.")
            with b:
                st.markdown("**Alert share by input order**")
                st.altair_chart(file_order_chart(flagged), use_container_width=True)
                st.caption("Each point is a sequential file batch, not a timestamp or live network time.")
            proto_plot = protocol_chart(df, flagged)
            if proto_plot is not None:
                st.markdown("**Most common protocols**")
                st.altair_chart(proto_plot, use_container_width=True)

            st.markdown("### Flow Investigation")
            rows = df.copy()
            rows.insert(0, "Flow #", np.arange(1, len(df) + 1))
            rows.insert(1, "Detection score", np.round(scores, 6))
            rows.insert(2, "Status", np.where(flagged, "Investigate", "No alert"))
            view = st.radio("Show flows", ["Alerts first", "Flagged only", "All records"], horizontal=True)
            if view == "Flagged only":
                displayed = rows.loc[flagged].sort_values("Detection score", ascending=False)
            elif view == "Alerts first":
                displayed = rows.sort_values("Detection score", ascending=False)
            else:
                displayed = rows
            visible_cols = ["Flow #", "Detection score", "Status"] + [
                c for c in ("proto", "service", "state", "dur", "sbytes", "dbytes", "label", "attack_cat") if c in rows.columns
            ]
            st.dataframe(displayed[visible_cols].head(400), use_container_width=True, hide_index=True)
            st.caption("The table shows at most 400 flows. Export for the complete scored batch.")
            st.download_button(
                "⬇ Export scored flows (CSV)", safe_export_csv(rows),
                file_name="zeroguard_threat_analysis.csv", mime="text/csv",
                use_container_width=False,
            )

            if "label" in df.columns:
                labels = pd.to_numeric(df["label"], errors="coerce")
                valid_labels = labels.isin([0, 1]).all()
                if valid_labels:
                    labels_int = labels.to_numpy(dtype=int)
                    benign = labels_int == 0
                    attacks = labels_int == 1
                    st.markdown("### Labeled Evaluation")
                    x, y = st.columns(2)
                    x.metric("Benign FPR", f"{100 * flagged[benign].mean():.2f}%" if benign.any() else "N/A")
                    y.metric("Attack recall", f"{100 * flagged[attacks].mean():.2f}%" if attacks.any() else "N/A")
                    if "attack_cat" in df.columns:
                        attack_names = df["attack_cat"].astype("string").str.strip()
                        withheld = (attack_names == withheld_family).fillna(False).to_numpy(dtype=bool) & attacks
                        if withheld.any():
                            st.metric("Held-out family recall", f"{100 * flagged[withheld].mean():.2f}%")
                    st.caption("Metrics apply only to this uploaded, labeled sample. They are not independent research validation.")
                else:
                    st.caption("Ground-truth labels must contain only 0 and 1 to calculate metrics.")
        except Exception as exc:
            st.error(f"Unable to analyze your file: {exc}")

with info_tab:
    st.subheader("System Overview")
    st.markdown(
        "ZeroGuard scores preprocessed **network-flow features** using a LightGBM classifier "
        "trained on UNSW-NB15 data. Uploads are scored in batches. Flows crossing a "
        "calibrated decision threshold are recommended for further investigation."
    )
    st.markdown("**Included capabilities**")
    st.markdown(
        "- Flow scoring, review queue and CSV export\n"
        "- Score distribution and protocol-level analytics\n"
        "- Optional, offline threshold review using independently verified benign data\n"
        "- Performance summaries when uploaded files include ground-truth labels"
    )
    st.markdown("**How to try the demo**")
    st.write(
        "Open Traffic Explorer, download the column template, and upload a CSV of "
        "prepared UNSW-NB15-style network flows. Review alerts and charts, then export "
        "the annotated CSV. A header-only template is not sample traffic."
    )
    st.markdown("**Deployment and operational boundaries**")
    st.info(
        "The application analyzes uploaded CSVs only. It does not intercept packets, "
        "identify a specific exploit, autonomously block traffic, or guarantee detection "
        "of previously unseen attacks. It is not validated as a production security control."
    )
    with st.expander("Model provenance and evaluation"):
        st.write("Bundle:", bundle.get("version", "Unknown"))
        st.write("Dataset:", bundle.get("origin", "UNSW-NB15"))
        st.write("Held-out family:", withheld_family)
        st.write("This family has already been inspected during development and is not an untouched final benchmark.")
        st.write("Threshold changes are session-only suggestions gated by separate known-attack guard scores.")
    st.caption("Use data only from networks you are authorized to analyze.")
