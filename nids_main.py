import streamlit as st
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score

# 1. Page Configuration
st.set_page_config(page_title="AI-Based NIDS Dashboard", layout="wide")
st.title("🛡️ AI-Powered Network Intrusion Detection System")

# 2. Data Loading / Simulation Logic (Section 5.1 & 5.2 of Manual)
def load_data():
    # Simulation mode as default [cite: 1, 44]
    np.random.seed(42)
    data_size = 1000
    data = {
        'packet_size': np.random.randint(40, 1500, data_size),
        'duration': np.random.uniform(0.01, 2.0, data_size),
        'protocol': np.random.choice([6, 17, 1], data_size), # TCP, UDP, ICMP
        'label': np.random.choice([0, 1], data_size, p=[0.8, 0.2]) # 0: Normal, 1: Intrusion
    }
    return pd.DataFrame(data)

# 3. Sidebar for Model Training (Section 6 of Manual)
st.sidebar.header("Control Panel")
if st.sidebar.button("Train Model Now"):
    df = load_data()
    X = df[['packet_size', 'duration', 'protocol']]
    y = df['label']
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)
    
    # Random Forest Implementation [cite: 1, 33]
    model = RandomForestClassifier(n_estimators=100)
    model.fit(X_train, y_train)
    
    st.session_state['model'] = model
    st.sidebar.success(f"Model trained! Accuracy: {accuracy_score(y_test, model.predict(X_test)):.2f}")

# 4. Live Traffic Simulator UI (Section 6.3 of Manual)
st.header("🔍 Live Traffic Simulator")
col1, col2, col3 = st.columns(3)

with col1:
    p_size = st.number_input("Packet Size (bytes)", min_value=40, max_value=1500, value=500)
with col2:
    dur = st.number_input("Duration (sec)", min_value=0.0, max_value=5.0, value=0.1)
with col3:
    proto = st.selectbox("Protocol", options=[6, 17, 1], format_func=lambda x: "TCP" if x==6 else "UDP" if x==17 else "ICMP")

if st.button("Analyze Packet"):
    if 'model' in st.session_state:
        prediction = st.session_state['model'].predict([[p_size, dur, proto]])
        if prediction[0] == 1:
            st.error("🚨 ALERT: Malicious Traffic Detected!")
        else:
            st.success("✅ Clear: Normal Traffic")
    else:
        st.warning("Please click 'Train Model Now' in the sidebar first.")