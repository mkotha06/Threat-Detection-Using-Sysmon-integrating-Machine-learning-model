import pandas as pd
import streamlit as st
import plotly.express as px
from cvss import CVSS3


# Sidebar for File Upload & Filters
st.sidebar.title("Data Input & Filters")
uploaded_file = st.sidebar.file_uploader("Upload CSV file", type=["csv"])

# Data Loading
# @st.cache_data
def load_data(path):
    df = pd.read_csv(path if path else "C:/Users/malav/Downloads/New_codes/preprocessed_logs.csv")

    # Decode numeric CKC_Stage codes to text labels
    code_to_stage = {
        1: "Benign",
        2: "Command and Control",
        3: "Delivery",
        4: "Exploitation",
        5: "Installation",
        0: "Actions on Objectives"
    }

    df["CKC_Stage"] = df["CKC_Stage"].map(code_to_stage).fillna("Unknown")

    # Construct Timestamp
    ts_cols = [c for c in df.columns if "timestamp" in c.lower() or "date" in c.lower()]
    if ts_cols:
        df["Timestamp"] = pd.to_datetime(df[ts_cols[0]], errors="coerce")
    elif {"year","month","day"}.issubset(df.columns):
        df["Timestamp"] = pd.to_datetime(
            df[["year","month","day"]].rename(columns={"year":"year","month":"month","day":"day"}),
            errors="coerce"
        )
    elif {"year","month"}.issubset(df.columns):
        df["Timestamp"] = pd.to_datetime(
            dict(year=df["year"], month=df["month"], day=1),
            errors="coerce"
        )
    else:
        df["Timestamp"] = pd.NaT

    # Map Stage to Severity & Color
    sev_map = {
        "Benign":"Unknown",
        "Actions on Objectives":"Critical",
        "Command and Control":"Critical",
        "Installation":"Medium",
        "Exploitation":"Medium",
        "Delivery":"Medium"
    }
    col_map = {
        "Benign":"gray",
        "Actions on Objectives":"red",
        "Command and Control":"red",
        "Installation":"orange",
        "Exploitation":"orange",
        "Delivery":"orange"
    }
    df["Severity"] = df["CKC_Stage"].map(sev_map).fillna("Unknown")
    df["Color"]    = df["CKC_Stage"].map(col_map).fillna("gray")

    # Ensure threat flag
    if "is_threat" not in df.columns:
        df["is_threat"] = df["CKC_Stage"].apply(lambda x: 0 if x == "Benign" else 1)

    return df, col_map

# Load and validate
try:
    df, stage_to_color = load_data(uploaded_file)
except Exception as e:
    st.sidebar.error(f"Error loading data: {e}")
    st.stop()

# CVSS Slider
cvss_col = next((c for c in ("CVSS","cvss_score","CVSS_Score") if c in df.columns), None)
if cvss_col:
    df[cvss_col] = pd.to_numeric(df[cvss_col], errors="coerce")
    lo, hi = float(df[cvss_col].min()), float(df[cvss_col].max())
    sel = st.sidebar.slider("CVSS Score Range", lo, hi, (lo, hi), step=0.1)
    df = df[df[cvss_col].between(*sel)]

# filters
stage_opts = ["All"] + sorted(df["CKC_Stage"].unique())
sev_opts   = ["All"] + sorted(df["Severity"].unique())
sel_stage  = st.sidebar.selectbox("CKC Stage", stage_opts)
sel_sev    = st.sidebar.selectbox("Severity", sev_opts)
chart_type = st.sidebar.radio("Chart Type", ["Pie","Bar"])

filtered = df.copy()
if sel_stage != "All":
    filtered = filtered[filtered["CKC_Stage"] == sel_stage]
if sel_sev != "All":
    filtered = filtered[filtered["Severity"] == sel_sev]

# Main Dashboard 
st.title(" SOC Threat Dashboard")

# 0) Overview: Total Logs vs Threats
st.subheader(" Logs vs Threats Overview")
stats = pd.DataFrame({
    "Category": ["Total Logs", "Total Threats"],
    "Count": [len(filtered), filtered[filtered["is_threat"]==1].shape[0]]
})
fig0 = px.bar(
    stats, x="Category", y="Count", text_auto=True,
    color="Category",
    color_discrete_map={"Total Logs":"lightgrey","Total Threats":"red"},
    title="Logs vs Confirmed Threats"
)
fig0.update_layout(showlegend=False, margin=dict(t=30,b=10))
st.plotly_chart(fig0, use_container_width=True)

# 1) Threat Summary
st.subheader(" Threat Summary")
threat_df = filtered[filtered["is_threat"] == 1]
if chart_type == "Pie":
    fig1 = px.pie(
        threat_df, names="CKC_Stage", color="CKC_Stage",
        color_discrete_map=stage_to_color, hole=0.3,
        title="Confirmed Threats by CKC Stage"
    )
    fig1.update_traces(textinfo="percent+value")
    st.plotly_chart(fig1, use_container_width=True)
else:
    cnt = threat_df["CKC_Stage"].value_counts().reset_index()
    cnt.columns = ["CKC_Stage","Count"]
    fig1 = px.bar(
        cnt, x="CKC_Stage", y="Count", text_auto=True,
        color="CKC_Stage", color_discrete_map=stage_to_color,
        title="Confirmed Threats by CKC Stage"
    )
    fig1.update_traces(textposition="outside")
    fig1.update_layout(showlegend=False, margin=dict(t=30,b=10))
    st.plotly_chart(fig1, use_container_width=True)

# 2) CVSS Distribution
if cvss_col:
    st.subheader(" CVSS Score Distribution")
    fig2 = px.histogram(
        threat_df, x=cvss_col, nbins=20,
        labels={cvss_col:"CVSS Score","count":"Events"}
    )
    st.plotly_chart(fig2, use_container_width=True)

# 3) Timeline
st.subheader(" CKC Events Over Time")
if not threat_df["Timestamp"].isna().all():
    if threat_df["Timestamp"].nunique() > 1:
        ts = threat_df.set_index("Timestamp").resample("D").size().reset_index(name="Count")
        fig3 = px.line(ts, x="Timestamp", y="Count", markers=True)
        fig3.update_layout(xaxis_title="Date", yaxis_title="Events", showlegend=False)
        st.plotly_chart(fig3, use_container_width=True)
    elif "hour_of_day" in threat_df.columns:
        hd = threat_df["hour_of_day"].value_counts().sort_index().reset_index()
        hd.columns = ["Hour","Count"]
        fig3 = px.bar(
            hd, x="Hour", y="Count", text_auto=True,
            labels={"Hour":"Hour of Day","Count":"Events"}
        )
        fig3.update_layout(showlegend=False)
        st.plotly_chart(fig3, use_container_width=True)
    else:
        st.info("Not enough date info for a timeline chart.")
else:
    st.info("No valid Timestamp found; skipping timeline.")

# 4) Event Table
st.subheader(" Event Table")
desired = ["Image","CommandLine","EventID","CKC_Stage"]
table_cols = [c for c in desired if c in filtered.columns]
if not table_cols:
    st.info("No columns available for the event table.")
else:
    st.dataframe(filtered[table_cols], use_container_width=True)