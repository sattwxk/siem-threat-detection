"""Streamlit dashboard for the Mini SIEM."""
import sqlite3
from pathlib import Path

import pandas as pd
import streamlit as st

DB_PATH = Path("siem.db")

st.set_page_config(page_title="Mini SIEM | SOC Dashboard", page_icon="🛡️", layout="wide")
st.title("🛡️ Mini SIEM & Threat Detection Lab")
st.caption("Local defensive security analytics • Synthetic/demo events recommended")

if not DB_PATH.exists():
    st.warning("No database found yet. Run the demo log generator and ingestion command first.")
    st.code("python generate_demo_logs.py\npython siem.py ingest sample_logs/auth_events.jsonl")
    st.stop()

try:
    with sqlite3.connect(str(DB_PATH)) as connection:
        events = pd.read_sql_query(
            "SELECT timestamp, event_type, source_ip, username, details FROM events ORDER BY timestamp DESC",
            connection,
        )
        alerts = pd.read_sql_query(
            "SELECT timestamp, severity, rule_name, source_ip, username, description FROM alerts ORDER BY timestamp DESC",
            connection,
        )
except sqlite3.Error as exc:
    st.error(f"Could not read the SIEM database: {exc}")
    st.stop()

if alerts.empty:
    st.info("No alerts yet. Import the included synthetic demo events to see detections.")

col1, col2, col3, col4 = st.columns(4)
col1.metric("Events ingested", len(events))
col2.metric("Alerts generated", len(alerts))
col3.metric("High severity", int((alerts["severity"] == "High").sum()) if not alerts.empty else 0)
col4.metric("Unique source IPs", events["source_ip"].nunique() if not events.empty else 0)

st.subheader("Alert investigation")
if not alerts.empty:
    severities = sorted(alerts["severity"].dropna().unique().tolist())
    selected_severities = st.multiselect("Severity", severities, default=severities)
    search_ip = st.text_input("Filter by source IP (optional)")
    filtered = alerts[alerts["severity"].isin(selected_severities)]
    if search_ip.strip():
        filtered = filtered[filtered["source_ip"].str.contains(search_ip.strip(), case=False, na=False)]
    st.dataframe(filtered, use_container_width=True, hide_index=True)
    st.download_button(
        "Download filtered alerts as CSV",
        data=filtered.to_csv(index=False).encode("utf-8"),
        file_name="siem_alerts.csv",
        mime="text/csv",
    )

st.subheader("Alert counts by rule")
if not alerts.empty:
    rule_counts = alerts["rule_name"].value_counts().rename_axis("Detection rule").reset_index(name="Alerts")
    st.bar_chart(rule_counts.set_index("Detection rule"))

st.subheader("Recent events")
if not events.empty:
    event_types = sorted(events["event_type"].dropna().unique().tolist())
    selected_types = st.multiselect("Event types", event_types, default=event_types)
    filtered_events = events[events["event_type"].isin(selected_types)]
    st.dataframe(filtered_events, use_container_width=True, hide_index=True)

st.divider()
st.caption("Educational prototype only. Alerts indicate activity to investigate; they do not prove compromise.")
