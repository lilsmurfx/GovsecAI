import streamlit as st
import pandas as pd
import plotly.express as px
import os

st.title('📊 Threat Stats')

# --- Load logs safely ---
logs_path = os.path.join("logs", "scans.csv")

if os.path.exists(logs_path):
    try:
        logs = pd.read_csv(logs_path)
    except Exception as e:
        st.warning(f"Error reading logs file: {e}")
        logs = pd.DataFrame({'timestamp': [], 'url': [], 'label': [], 'score': []})
else:
    logs = pd.DataFrame({'timestamp': [], 'url': [], 'label': [], 'score': []})

# Ensure 'label' column exists
if 'label' not in logs.columns:
    logs['label'] = []

# --- Recent scans table ---
st.subheader('Recent scans')
if logs.empty:
    st.info('No scans yet. Use the Analyzer to run a URL check.')
else:
    st.dataframe(logs.sort_values('timestamp', ascending=False).head(50))

# --- Sample distribution pie chart ---
st.subheader('Sample distribution')
if logs.empty:
    # Show sample static chart if no logs
    sample = pd.DataFrame({
        'Category': ['Safe', 'Suspicious', 'Malicious'],
        'Count': [120, 35, 22]
    })
    fig = px.pie(sample, names='Category', values='Count', title='Detected Threats Overview')
else:
    # Ensure label values are consistent
    def map_label(x):
        if x in [0, '0', 'Safe']:
            return 'Safe'
        elif x in [1, '1', 'Malicious']:
            return 'Malicious'
        else:
            return 'Other'

    logs['label'] = logs['label'].apply(map_label)
    
    # Aggregate counts
    agg = logs['label'].value_counts().rename_axis('label').reset_index(name='Count')
    
    fig = px.pie(agg, names='label', values='Count', title='Detected Threats Overview')

st.plotly_chart(fig, use_container_width=True)
