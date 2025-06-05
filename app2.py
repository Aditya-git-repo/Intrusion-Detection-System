import streamlit as st
import pandas as pd
import numpy as np
import joblib
from pymongo import MongoClient
from datetime import datetime
import hashlib

# MongoDB connection
client = MongoClient("mongodb+srv://aditya87532:aditya789@cluster0.is5qwaq.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0")
db = client["intrusion_detection"]
users_col = db["users"]
predictions_col = db["predictions"]

# Load model and scaler
model = joblib.load("best_final_model.pkl")
scaler = joblib.load("scaler.pkl")

# Feature names
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

# Utility: hash password
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Register user
def register_user(username, email, password):
    if users_col.find_one({"email": email}):
        return False, "Email already registered."
    users_col.insert_one({
        "username": username,
        "email": email,
        "password": hash_password(password)
    })
    return True, "Registration successful."

# Authenticate user
def authenticate_user(email, password):
    user = users_col.find_one({"email": email})
    if user and user["password"] == hash_password(password):
        return True, user
    return False, None

# Streamlit app setup
st.set_page_config(page_title="Intrusion Detection System", layout="wide")

# Initialize session
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False
    st.session_state.email = None
    st.session_state.username = None
    st.session_state.view_history = False

# Login Page
def login_page():
    st.title("🔐 Login to Intrusion Detection System")
    email = st.text_input("📧 Email")
    password = st.text_input("🔑 Password", type="password")

    if st.button("🔓 Login"):
        authenticated, user = authenticate_user(email, password)
        if authenticated:
            st.session_state.authenticated = True
            st.session_state.email = email
            st.session_state.username = user["username"]
            st.success(f"🔓 Logged in as {user['username']}")
            st.rerun()
        else:
            st.error("❌ Invalid email or password.")

    st.markdown("Don't have an account?")
    if st.button("📝 Register Here"):
        st.session_state.register = True
        st.rerun()

# Register Page
def register_page():
    st.title("📝 Register for Intrusion Detection System")
    username = st.text_input("👤 Username")
    email = st.text_input("📧 Email")
    password = st.text_input("🔒 Password", type="password")
    confirm = st.text_input("🔁 Confirm Password", type="password")

    if st.button("✅ Register"):
        if password != confirm:
            st.error("❌ Passwords do not match.")
        else:
            success, msg = register_user(username, email, password)
            if success:
                st.success(msg)
                st.session_state.register = False
                st.rerun()
            else:
                st.error(msg)

    st.markdown("Already have an account?")
    if st.button("🔙 Back to Login"):
        st.session_state.register = False
        st.rerun()

# History Page
def history_page():
    st.title("📜 Prediction History")
    history = list(predictions_col.find({"email": st.session_state.email}).sort("timestamp", -1))
    if not history:
        st.info("No previous predictions found.")
    else:
        for record in history:
            st.markdown(f"""
            - **Date**: {record['timestamp']}
            - **Result**: `{record['result']}`
            - **Location**: {record['location']}
            - **Name**: {record['name']}
            - **Inputs**: *{record['inputs'][:5]}...* (total {len(record['inputs'])} features)
            """)
            st.markdown("---")

    if st.button("🔙 Back to Prediction"):
        st.session_state.view_history = False
        st.rerun()

# Prediction Page
def prediction_page():
    st.markdown(f"<h2 style='text-align: center;'>🔒 Intrusion Detection System</h2>", unsafe_allow_html=True)
    st.markdown("<p style='text-align: center;'>Enter details to predict network traffic status.</p>", unsafe_allow_html=True)

    # Sidebar
    st.sidebar.markdown(f"👋 Welcome, **{st.session_state.username}**")
    if st.sidebar.button("📜 View History"):
        st.session_state.view_history = True
        st.rerun()
    if st.sidebar.button("🚪 Logout"):
        st.session_state.authenticated = False
        st.session_state.email = None
        st.session_state.username = None
        st.rerun()

    st.markdown("---")

    input_mode = st.radio("Choose input method:", ["🔘 Comma-Separated Line", "🧾 Individual Fields"])
    name = st.text_input("👤 Your Name")
    location = st.text_input("📍 Your Location")
    inputs = []

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

                    predictions_col.insert_one({
                        "email": st.session_state.email,
                        "name": name,
                        "location": location,
                        "inputs": values,
                        "result": result,
                        "timestamp": timestamp
                    })

            except Exception as e:
                st.error(f"⚠️ Error: {e}")

    else:
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

                    predictions_col.insert_one({
                        "email": st.session_state.email,
                        "name": name,
                        "location": location,
                        "inputs": inputs,
                        "result": result,
                        "timestamp": timestamp
                    })

                except Exception as e:
                    st.error(f"⚠️ Error during prediction: {e}")

# Control routing
if not st.session_state.authenticated:
    if "register" in st.session_state and st.session_state.register:
        register_page()
    else:
        login_page()
else:
    if st.session_state.view_history:
        history_page()
    else:
        prediction_page()

# Footer
st.markdown(
    """
    <div style='position: fixed; bottom: 10px; right: 10px; font-size: 12px; color: gray;'>
        Developed by <b>Budhaditya Mukherjee</b> | 📧 <a href='mailto:aditya875320@gmail.com'>aditya875320@gmail.com</a>
    </div>
    """,
    unsafe_allow_html=True
)
