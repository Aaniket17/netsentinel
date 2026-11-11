import streamlit as st
import pandas as pd
import numpy as np
import joblib
import os

# Set page configuration
st.set_page_config(page_title="NetSentinel | Anomaly Detection", layout="wide")

st.title("NetSentinel: Network Anomaly Detection System")
st.markdown("Real-time network traffic flow inspection and bulk PCAP/CSV anomaly scanning.")

# Load trained baseline model
@st.cache_resource
def load_model():
    model_path = os.path.join("models", "baseline_rf.joblib")
    if os.path.exists(model_path):
        return joblib.load(model_path)
    return None

model = load_model()

if model is None:
    st.error("Model not found in 'models/' folder. Please ensure baseline_rf.joblib exists.")
    st.stop()

# Load schema features
data_path = os.path.join("data", "processed", "cleaned_ddos_flows.parquet")
sample_df = pd.read_parquet(data_path).drop(columns=['Label'])
feature_columns = sample_df.columns.tolist()

# Tabs for Single Flow Inspection vs Bulk CSV Scanning
tab1, tab2 = st.tabs(["Single Flow Inspector", "Batch CSV Traffic Scanner"])

with tab1:
    col1, col2 = st.columns([2, 1])

    with col1:
        st.subheader("Manual Flow Parameters")
        fwd_len_max = st.number_input("Fwd Packet Length Max", min_value=0.0, value=20.0, step=1.0)
        avg_seg_size = st.number_input("Avg Fwd Segment Size", min_value=0.0, value=6.0, step=0.5)
        fwd_len_mean = st.number_input("Fwd Packet Length Mean", min_value=0.0, value=6.0, step=0.5)
        fwd_act_packets = st.number_input("Fwd Act Data Packets", min_value=0.0, value=1.0, step=1.0)
        init_win_bytes = st.number_input("Init Fwd Win Bytes", min_value=0.0, value=256.0, step=10.0)

        # Build dummy vector with median baseline values
        input_vector = sample_df.median().to_dict()
        input_vector['Fwd Packet Length Max'] = fwd_len_max
        input_vector['Avg Fwd Segment Size'] = avg_seg_size
        input_vector['Fwd Packet Length Mean'] = fwd_len_mean
        input_vector['Fwd Act Data Packets'] = fwd_act_packets
        input_vector['Init Fwd Win Bytes'] = init_win_bytes

        input_df = pd.DataFrame([input_vector])[feature_columns]

        if st.button("Analyze Single Flow", type="primary"):
            prediction = model.predict(input_df)[0]
            proba = model.predict_proba(input_df)[0]

            if prediction == 1:
                st.error(f"ANOMALY DETECTED: DDoS Traffic (Confidence: {proba[1]*100:.2f}%)")
            else:
                st.success(f"NORMAL FLOW: Benign Traffic (Confidence: {proba[0]*100:.2f}%)")

    with col2:
        st.subheader("Model Summary")
        st.info("**Algorithm:** Random Forest Classifier\n\n**Trained Classes:** Benign (0), DDoS (1)\n\n**Features Evaluated:** 68")

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
                batch_df[c] = sample_df[c].median()

        batch_X = batch_df[feature_columns]

        if st.button("Run Batch Anomaly Scan"):
            batch_preds = model.predict(batch_X)
            batch_df['Detection_Status'] = np.where(batch_preds == 1, 'DDoS Attack', 'Benign')

            attack_count = (batch_preds == 1).sum()
            benign_count = (batch_preds == 0).sum()

            c1, c2 = st.columns(2)
            c1.metric("Anomalous Flows (DDoS)", attack_count)
            c2.metric("Normal Flows (Benign)", benign_count)

            st.dataframe(batch_df[['Detection_Status'] + [c for c in ['Flow Duration', 'Fwd Packet Length Max'] if c in batch_df.columns]].head(50))