import streamlit as st
import numpy as np
import pandas as pd
import joblib
from datetime import datetime
from pymongo import MongoClient

# MongoDB connection
client = MongoClient(
    "mongodb+srv://aditya87532:aditya789@cluster0.is5qwaq.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0")
db = client["intrusion_detection"]
collection = db["predictions"]

# Load model and scaler
model = joblib.load("best_final_model.pkl")
scaler = joblib.load("scaler.pkl")

# Streamlit UI setup
st.set_page_config(page_title="Intrusion Detection System", layout="wide")
st.markdown("<h1 style='text-align: center;'>🔒 Intrusion Detection System</h1>", unsafe_allow_html=True)
st.markdown("<p style='text-align: center;'>Choose an input method to predict intrusion detection.</p>",
            unsafe_allow_html=True)
st.markdown("---")

# Feature list
feature_names = [
    "Flow Duration", "Total Fwd Packets", "Total Backward Packets", "Total Length of Fwd Packets",
    "Total Length of Bwd Packets", "Fwd Packet Length Max", "Fwd Packet Length Min", "Fwd Packet Length Mean",
    "Fwd Packet Length Std", "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean",
    "Bwd Packet Length Std", "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max",
    "Flow IAT Min", "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min", "Bwd IAT Total",
    "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min", "Fwd PSH Flags", "Bwd PSH Flags", "Fwd URG Flags",
    "Bwd URG Flags", "Fwd Header Length", "Bwd Header Length", "Fwd Packets/s", "Bwd Packets/s", "Min Packet Length",
    "Max Packet Length", "Packet Length Mean", "Packet Length Std", "Packet Length Variance", "FIN Flag Count",
    "SYN Flag Count", "RST Flag Count", "PSH Flag Count", "ACK Flag Count", "URG Flag Count", "CWE Flag Count",
    "ECE Flag Count", "Down/Up Ratio", "Average Packet Size", "Avg Fwd Segment Size", "Avg Bwd Segment Size",
    "Fwd Header Length.1", "Fwd Avg Bytes/Bulk", "Fwd Avg Packets/Bulk", "Fwd Avg Bulk Rate", "Bwd Avg Bytes/Bulk",
    "Bwd Avg Packets/Bulk", "Bwd Avg Bulk Rate", "Subflow Fwd Packets", "Subflow Fwd Bytes", "Subflow Bwd Packets",
    "Subflow Bwd Bytes", "Init_Win_bytes_forward", "Init_Win_bytes_backward", "act_data_pkt_fwd",
    "min_seg_size_forward", "Active Mean", "Active Std", "Active Max", "Active Min", "Idle Mean", "Idle Std",
    "Idle Max", "Idle Min"
]

# Input mode
input_mode = st.radio("Choose input method:", ["🔘 Comma-Separated Line", "🧾 Individual Fields"])
inputs = []

# Collect common inputs
name = st.text_input("👤 Your Name")
location = st.text_input("📍 Your Location")

if input_mode == "🔘 Comma-Separated Line":
    user_input = st.text_area("Enter all 78 values (comma-separated)", height=150)

    if st.button("🔍 Predict Intrusion"):
        try:
            values = list(map(float, user_input.strip().split(',')))
            if len(values) != len(feature_names):
                st.error(f"❌ Expected {len(feature_names)} values, but got {len(values)}.")
            elif not name or not location:
                st.error("❌ Please enter your name and location.")
            else:
                df = pd.DataFrame([values], columns=feature_names)
                df_scaled = scaler.transform(df)
                prediction = model.predict(df_scaled)[0]
                result = "Intrusion Detected" if prediction == 1 else "Normal Traffic"
                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

                st.success(f"✅ Prediction: **{result}**")
                st.info(f"🕒 Timestamp: {timestamp}")

                collection.insert_one({
                    "name": name,
                    "location": location,
                    "inputs": values,
                    "result": result,
                    "timestamp": timestamp
                })

        except Exception as e:
            st.error(f"⚠️ Error: {e}")

elif input_mode == "🧾 Individual Fields":
    st.subheader("Input Features")
    cols = st.columns(3)
    for i, feature in enumerate(feature_names):
        with cols[i % 3]:
            val = st.text_input(f"{feature}", key=feature)
            try:
                val = float(val)
                inputs.append(val)
            except:
                inputs.append(None)

    if st.button("🔍 Predict Intrusion"):
        if None in inputs:
            st.error("❌ Please fill in all fields with valid numbers.")
        elif not name or not location:
            st.error("❌ Please enter your name and location.")
        else:
            try:
                df = pd.DataFrame([inputs], columns=feature_names)
                df_scaled = scaler.transform(df)
                prediction = model.predict(df_scaled)[0]
                result = "Intrusion Detected" if prediction == 1 else "Normal Traffic"
                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

                st.success(f"✅ Prediction: **{result}**")
                st.info(f"🕒 Timestamp: {timestamp}")

                collection.insert_one({
                    "name": name,
                    "location": location,
                    "inputs": inputs,
                    "result": result,
                    "timestamp": timestamp
                })

            except Exception as e:
                st.error(f"⚠️ Error during prediction: {e}")

# Developer credit in bottom right corner
st.markdown(
    """
    <div style='position: fixed; bottom: 10px; right: 10px; font-size: 12px; color: gray;'>
        Developed by <b>Budhaditya Mukherjee</b> | 📧 <a href='mailto:aditya875320@gmail.com'>aditya875320@gmail.com</a>
    </div>
    """,
    unsafe_allow_html=True
)
