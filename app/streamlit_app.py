import os
import threading
import webbrowser
import joblib
import numpy as np
import pandas as pd
import streamlit as st

# Set page configuration
st.set_page_config(page_title="NetSentinel | Multi-Class Anomaly Detection", layout="wide")

# Auto-open browser once on local launch
if os.environ.get("STREAMLIT_BROWSER_OPENED") != "1" and os.name == "nt":
    os.environ["STREAMLIT_BROWSER_OPENED"] = "1"
    threading.Timer(1.5, lambda: webbrowser.open("http://localhost:8501")).start()

st.title("NetSentinel: Multi-Class Network Anomaly Detection System")
st.markdown("Real-time network traffic flow inspection and multi-attack CSV anomaly scanning.")

# Resolve project root directory dynamically
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Load trained multi-class model
@st.cache_resource
def load_model():
    model_path = os.path.join(BASE_DIR, "models", "baseline_rf.joblib")
    if os.path.exists(model_path):
        return joblib.load(model_path)
    return None

model = load_model()

if model is None:
    st.error("Model not found in 'models/' folder. Please ensure baseline_rf.joblib exists.")
    st.stop()

# Load schema features, baseline medians, and real sample presets per attack class
@st.cache_data
def load_baseline_and_presets():
    processed_path = os.path.join(BASE_DIR, "data", "processed", "cleaned_ddos_flows.parquet")
    raw_path = os.path.join(BASE_DIR, "data", "raw", "DDoS-Friday-no-metadata.parquet")
    csv_path = os.path.join(BASE_DIR, "sample_traffic.csv")

    if os.path.exists(processed_path):
        df = pd.read_parquet(processed_path)
    elif os.path.exists(csv_path):
        df = pd.read_csv(csv_path)
    elif os.path.exists(raw_path):
        df = pd.read_parquet(raw_path)
    else:
        return None, None, {}

    df.columns = df.columns.str.strip()

    # Standardize labels if raw/csv file is used as fallback
    def normalize_lbl(val):
        s = str(val).strip()
        u = s.upper()
        if u == "BENIGN":
            return "Benign"
        elif "DDOS" in u:
            return "DDoS"
        elif "DOS" in u:
            return "DoS"
        elif "PORTSCAN" in u:
            return "Portscan"
        elif "BOT" in u:
            return "Botnet"
        elif "PATATOR" in u or "BRUTE" in u:
            return "Bruteforce"
        elif "WEB ATTACK" in u or "XSS" in u or "SQL" in u:
            return "WebAttacks"
        elif "INFILTRATION" in u:
            return "Infiltration"
        return s

    presets = {}
    if "Label" in df.columns:
        df["Clean_Label"] = df["Label"].apply(normalize_lbl)
        for lbl, group in df.groupby("Clean_Label"):
            sample_row = (
                group.drop(columns=["Label", "Clean_Label"])
                .replace([np.inf, -np.inf], np.nan)
                .fillna(0.0)
                .iloc[0]
            )
            presets[lbl] = sample_row.to_dict()
        df_features = df.drop(columns=["Label", "Clean_Label"])
    else:
        df_features = df

    # Keep only numeric columns matching trained model features
    if hasattr(model, "feature_names_in_"):
        cols = list(model.feature_names_in_)
        for c in cols:
            if c not in df_features.columns:
                df_features[c] = 0.0
        df_features = df_features[cols]

    df_features = df_features.replace([np.inf, -np.inf], np.nan)
    medians = df_features.median(numeric_only=True).fillna(0.0).to_dict()
    return list(df_features.columns), medians, presets

feature_columns, baseline_medians, attack_presets = load_baseline_and_presets()

if feature_columns is None:
    st.error("Baseline dataset not found. Please check data/ or sample_traffic.csv.")
    st.stop()

# Extract trained class names dynamically
trained_classes = [str(c) for c in getattr(model, "classes_", ["Benign", "Attack"])]

# Tabs for Single Flow Inspection vs Bulk CSV Scanning
tab1, tab2 = st.tabs(["Single Flow Inspector", "Batch CSV Traffic Scanner"])

with tab1:
    col1, col2 = st.columns([2, 1])

    with col1:
        st.subheader("Flow Parameters & Quick Attack Presets")
        preset_options = ["Custom Manual Input"] + sorted(list(attack_presets.keys()))
        selected_preset = st.selectbox(
            "Select a Traffic Preset (or choose Custom Manual Input):",
            preset_options,
        )

        # Pick base vector either from selected attack preset or median defaults
        if selected_preset != "Custom Manual Input" and selected_preset in attack_presets:
            base_vector = {c: float(attack_presets[selected_preset].get(c, 0.0)) for c in feature_columns}
            st.caption(f"Loaded real network packet signature for **{selected_preset}**.")
        else:
            base_vector = baseline_medians.copy()

        fwd_len_max = st.number_input(
            "Fwd Packet Length Max",
            min_value=0.0,
            value=float(base_vector.get("Fwd Packet Length Max", 20.0)),
            step=1.0,
        )
        avg_seg_size = st.number_input(
            "Avg Fwd Segment Size",
            min_value=0.0,
            value=float(base_vector.get("Avg Fwd Segment Size", 6.0)),
            step=0.5,
        )
        fwd_len_mean = st.number_input(
            "Fwd Packet Length Mean",
            min_value=0.0,
            value=float(base_vector.get("Fwd Packet Length Mean", 6.0)),
            step=0.5,
        )
        fwd_act_packets = st.number_input(
            "Fwd Act Data Packets",
            min_value=0.0,
            value=float(base_vector.get("Fwd Act Data Packets", 1.0)),
            step=1.0,
        )
        init_win_bytes = st.number_input(
            "Init Fwd Win Bytes",
            min_value=0.0,
            value=float(base_vector.get("Init Fwd Win Bytes", 256.0)),
            step=10.0,
        )

        # Update input vector with UI values
        input_vector = base_vector.copy()
        input_vector["Fwd Packet Length Max"] = fwd_len_max
        input_vector["Avg Fwd Segment Size"] = avg_seg_size
        input_vector["Fwd Packet Length Mean"] = fwd_len_mean
        input_vector["Fwd Act Data Packets"] = fwd_act_packets
        input_vector["Init Fwd Win Bytes"] = init_win_bytes

        input_df = pd.DataFrame([input_vector])[feature_columns]

        if st.button("Analyze Single Flow", type="primary"):
            prediction = str(model.predict(input_df)[0])
            proba = model.predict_proba(input_df)[0]
            confidence = float(np.max(proba)) * 100

            if prediction.upper() == "BENIGN":
                st.success(f"NORMAL FLOW: {prediction} Traffic (Confidence: {confidence:.2f}%)")
            else:
                st.error(f"ANOMALY DETECTED: {prediction} Attack (Confidence: {confidence:.2f}%)")

            # Show probability breakdown across all trained classes
            prob_df = pd.DataFrame(
                {
                    "Traffic Category": trained_classes,
                    "Confidence (%)": np.round(proba * 100, 2),
                }
            ).sort_values(by="Confidence (%)", ascending=False)
            st.dataframe(prob_df, width="stretch", hide_index=True)

    with col2:
        st.subheader("Model Summary")
        classes_str = ", ".join(trained_classes)
        st.info(
            f"**Algorithm:** Random Forest Classifier\n\n"
            f"**Trained Classes ({len(trained_classes)}):** {classes_str}\n\n"
            f"**Features Evaluated:** {len(feature_columns)}"
        )

with tab2:
    st.subheader("Upload Network Traffic File (.csv)")
    uploaded_file = st.file_uploader("Upload flow records CSV", type=["csv"])

    if uploaded_file is not None:
        batch_df = pd.read_csv(uploaded_file)
        batch_df.columns = batch_df.columns.str.strip()
        st.write(f"Loaded {len(batch_df)} network flow records.")

        # Match columns with training schema
        missing_cols = [c for c in feature_columns if c not in batch_df.columns]
        if missing_cols:
            st.warning(f"File missing {len(missing_cols)} schema columns. Filling with baseline medians.")
            for c in missing_cols:
                batch_df[c] = baseline_medians.get(c, 0.0)

        batch_X = batch_df[feature_columns].replace([np.inf, -np.inf], np.nan).fillna(0.0)

        if st.button("Run Batch Anomaly Scan", type="primary"):
            batch_preds = model.predict(batch_X).astype(str)
            batch_probas = np.max(model.predict_proba(batch_X), axis=1) * 100

            batch_df["Predicted_Attack_Type"] = batch_preds
            batch_df["Confidence (%)"] = np.round(batch_probas, 2)

            is_attack = np.char.upper(batch_preds) != "BENIGN"
            attack_count = int(is_attack.sum())
            benign_count = int((~is_attack).sum())

            c1, c2, c3 = st.columns(3)
            c1.metric("Total Flows Scanned", len(batch_df))
            c2.metric("Anomalous Flows Detected", attack_count)
            c3.metric("Normal Flows (Benign)", benign_count)

            # Display category breakdown
            st.subheader("Detected Traffic Breakdown")
            breakdown_df = (
                pd.Series(batch_preds)
                .value_counts()
                .rename_axis("Traffic Category")
                .reset_index(name="Flow Count")
            )
            st.bar_chart(breakdown_df.set_index("Traffic Category"))

            # Display scan results table
            preview_cols = ["Predicted_Attack_Type", "Confidence (%)"]
            if "Label" in batch_df.columns:
                preview_cols.insert(0, "Label")
            extra_cols = [c for c in ["Flow Duration", "Fwd Packet Length Max"] if c in batch_df.columns]
            st.dataframe(batch_df[preview_cols + extra_cols].head(100), width="stretch")

            # Allow downloading full scan report
            csv_output = batch_df.to_csv(index=False).encode("utf-8")
            st.download_button(
                label="Download Full Scan Report (.csv)",
                data=csv_output,
                file_name="netsentinel_scan_report.csv",
                mime="text/csv",
            )