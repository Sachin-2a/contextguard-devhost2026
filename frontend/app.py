import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import streamlit as st
import pandas as pd
from backend.database import init_db, fetch_audit_logs
from backend.main import inspect_and_process, GatewayRequest, ContextEnvelope
from backend.policy_engine import load_policy_matrix, save_policy_matrix

# Page Configuration
st.set_page_config(
    page_title="ContextGuard Enterprise | AI Security & Data Privacy Gateway",
    layout="wide",
    page_icon="🛡️"
)

init_db()

# App Header
st.title("🛡️ ContextGuard Enterprise Gateway")
st.caption("Autonomous AI Governance & Context-Aware Data Loss Prevention (DLP)[cite: 5]")

# Sidebar for Enterprise Controls & Status
with st.sidebar:
    st.header("🏢 Enterprise Console")
    st.success("🟢 Gateway Status: Online\n\n⚡ Engine: Active (3-Layer + Policy)")
    st.markdown("---")
    st.subheader("🎛️ Global Guardrails")
    strict_mode = st.toggle("Strict DPDP Act Compliance[cite: 5]", value=True)
    auto_vault = st.toggle("Token Vault Auto-De-tokenization", value=True)
    st.markdown("---")
    st.subheader("👥 Active Tenant")
    st.text("Org: Enterprise Corp (IN-BLR)\nLicense: Developer Tier\nAPI Latency: 24ms")

# Pre-configured Demo Scenarios from the Pitch Deck / Team Brief
DEMO_SCENARIOS = {
    "-- Select a Hackathon Demo Scenario --": None,
    "1. Salary in HR Private Thread (Allowed)": {
        "text": "Her salary is 18 LPA.",
        "role": "HR Manager",
        "source": "HR Portal Message",
        "dest": "HR_PRIVATE",
        "purpose": "Internal compensation verification"
    },
    "2. Same Salary in Public Channel / External AI (Redacted/Blocked)": {
        "text": "Her salary is 18 LPA.",
        "role": "Team Member",
        "source": "Public Slack Channel",
        "dest": "PUBLIC_CHANNEL",
        "purpose": "Drafting public team announcement"
    },
    "3. Hidden Health Detail — No Obvious Keyword (Detected & Redacted)": {
        "text": "The report on my sugar levels came back high.",
        "role": "Employee",
        "source": "Shared Team Chat",
        "dest": "PUBLIC_CHANNEL",
        "purpose": "Rewriting message"
    },
    "4. E-Commerce Order ID — False Positive Guard (Allowed)": {
        "text": "Order 4521 1234 5678 shipped.",
        "role": "Support Agent",
        "source": "Customer Ticket",
        "dest": "EXTERNAL_AI_API",
        "purpose": "Generate customer tracking update"
    },
    "5. Long Email Thread — Selective Pseudonymization & Vault Restore": {
        "text": (
            "Hi team, please prepare the onboarding summary for Ananya Sharma (ananya.sharma@corp.in, "
            "+91 9876543210). Her approved compensation is 18 LPA and her PAN is ABCDE1234F."
        ),
        "role": "HR Manager",
        "source": "Internal Email Thread",
        "dest": "INTERNAL_SUMMARY",
        "purpose": "Summarize thread via AI Assistant"
    }
}

tab1, tab2, tab3 = st.tabs(["⚡ Live Gateway Inspection", "⚙️ Policy Rules & Matrix", "📋 Audit Logs & Compliance"])

with tab1:
    selected_demo = st.selectbox("🎯 **Quick Pitch Demo Scenario Selector:**", list(DEMO_SCENARIOS.keys()))

    default_text = "Type or paste your message or document snippet here..."
    default_role = "HR Manager"
    default_source = "Internal Email"
    default_dest = "EXTERNAL_AI_API"
    default_purpose = "General Query"

    if selected_demo and DEMO_SCENARIOS[selected_demo]:
        scen = DEMO_SCENARIOS[selected_demo]
        default_text = scen["text"]
        default_role = scen["role"]
        default_source = scen["source"]
        default_dest = scen["dest"]
        default_purpose = scen["purpose"]

    st.divider()

    col_input, col_env = st.columns(2, gap="large")

    with col_input:
        st.subheader("💬 1. Inbound Prompt / Payload")
        user_text = st.text_area(
            "Text sent by user/system into AI tool:",
            value=default_text,
            height=160
        )
        run_btn = st.button("🚀 Intercept & Inspect Payload", type="primary", use_container_width=True)

    with col_env:
        st.subheader("📦 2. Context Envelope Metadata[cite: 3, 5]")
        with st.container(border=True):
            role = st.selectbox(
                "Requester Role", 
                ["HR Manager", "Employee", "Support Agent", "Developer", "External Contractor"],
                index=["HR Manager", "Employee", "Support Agent", "Developer", "External Contractor"].index(default_role) if default_role in ["HR Manager", "Employee", "Support Agent", "Developer", "External Contractor"] else 0
            )
            source = st.text_input("Data Source", value=default_source)
            dest = st.selectbox(
                "Destination Channel", 
                ["HR_PRIVATE", "INTERNAL_SUMMARY", "PUBLIC_CHANNEL", "EXTERNAL_AI_API"],
                index=["HR_PRIVATE", "INTERNAL_SUMMARY", "PUBLIC_CHANNEL", "EXTERNAL_AI_API"].index(default_dest) if default_dest in ["HR_PRIVATE", "INTERNAL_SUMMARY", "PUBLIC_CHANNEL", "EXTERNAL_AI_API"] else 0,
                help="Where is this data heading? External APIs carry higher risk."
            )
            purpose = st.text_input("Processing Purpose", value=default_purpose)

    if run_btn:
        with st.spinner("Executing 3-Layer Detection & Policy Evaluation...[cite: 3, 5]"):
            req = GatewayRequest(
                text=user_text,
                envelope=ContextEnvelope(requester_role=role, data_source=source, destination=dest, purpose=purpose),
                authorised_to_restore=auto_vault
            )
            res = inspect_and_process(req)

        st.divider()
        st.subheader("📊 Inspection & Enforcement Summary")

        # Metrics Row
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Sensitivity Category", res["classification"]["sensitivity_category"])
        m2.metric("Risk Level", res["classification"]["risk_level"])
        m3.metric("Policy Action", res["policy_action"])
        m4.metric("Entities Flagged", len(res["detections"]))

        # Explanation Banner
        st.info(f"**🧠 Contextual Reasoning Engine:** {res['classification']['reason']}")

        # Split View Comparison
        col_res1, col_res2 = st.columns(2)
        
        with col_res1:
            st.markdown("#### 🔍 Detection Breakdown (Layers 1-3)")
            if res["detections"]:
                st.dataframe(
                    pd.DataFrame(res["detections"])[["layer", "entity_type", "text", "confidence"]],
                    use_container_width=True,
                    hide_index=True
                )
            else:
                st.success("No policy violations or sensitive entities flagged.")

        with col_res2:
            st.markdown("#### 🔄 Payload Transformation & Output Guard")
            st.text("Sanitized prompt sent to LLM API:")
            st.code(res["prompt_sent_to_llm"], language="text")
            
            st.text("Final response returned to user (De-tokenized):")
            st.success(res["output_guard"]["final_user_output"])

with tab2:
    st.subheader("⚙️ Editable Policy Matrix Engine")
    st.markdown("Define mapping rules for Sensitivity Category × Destination Channel[cite: 3, 5].")
    
    matrix = load_policy_matrix()
    df_matrix = pd.DataFrame(matrix).T
    edited_df = st.data_editor(df_matrix, use_container_width=True)
    
    if st.button("💾 Deploy Policy Update"):
        save_policy_matrix(edited_df.to_dict(orient="index"))
        st.success("✅ Policy matrix successfully updated across cluster!")

with tab3:
    st.subheader("📋 Compliance Audit Trail & Live Counters")
    st.markdown("Immutable audit log recording every gateway interception for DPDP Act and enterprise compliance[cite: 3, 5].")
    
    logs = fetch_audit_logs(100)
    if logs:
        df_logs = pd.DataFrame(logs)
        c_allow = (df_logs["action_taken"] == "ALLOW").sum()
        c_redact = (df_logs["action_taken"] == "REDACT").sum()
        c_pseudo = (df_logs["action_taken"] == "PSEUDONYMIZE").sum()
        c_block = (df_logs["action_taken"].isin(["BLOCK", "ESCALATE"])).sum()

        k1, k2, k3, k4 = st.columns(4)
        k1.metric("Allowed Requests", int(c_allow))
        k2.metric("Redacted Payloads", int(c_redact))
        k3.metric("Pseudonymized", int(c_pseudo))
        k4.metric("Blocked / Escalated", int(c_block))

        st.divider()
        st.dataframe(
            df_logs[["id", "timestamp", "requester_role", "destination", "sensitivity_category", "risk_level", "action_taken", "reason"]],
            use_container_width=True,
            hide_index=True
        )
    else:
        st.info("No audit entries recorded yet. Run a scenario in Tab 1.")
