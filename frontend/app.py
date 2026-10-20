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
    page_title="ContextGuard | AI Privacy Gateway",
    layout="wide",
    page_icon="🛡️"
)

init_db()

# Custom UI Styling for a cleaner look
st.markdown("""
    <style>
    .main-header {
        font-size: 2.2rem;
        color: #1E3A8A;
        font-weight: 700;
        margin-bottom: 0rem;
    }
    .sub-header {
        font-size: 1.1rem;
        color: #4B5563;
        margin-bottom: 1.5rem;
    }
    .card {
        padding: 1.2rem;
        border-radius: 0.5rem;
        background-color: #F3F4F6;
        border: 1px solid #E5E7EB;
        margin-bottom: 1rem;
    }
    </style>
""", unsafe_allow_html=True)

# Header Section
st.markdown('<p class="main-header">🛡️ ContextGuard</p>', unsafe_allow_html=True)
st.markdown('<p class="sub-header">Context-Aware AI Privacy Gateway — Privacy that understands intent, not just patterns[cite: 5].</p>', unsafe_allow_html=True)

# Top Explainer Banner for Judges & Users
with st.container():
    st.info(
        "💡 **How it works:** When users paste emails, chats, or documents into AI tools, ContextGuard checks "
        "the **Context Envelope** (who is asking, where the data is going) combined with a **3-Layer Detection Pipeline** "
        "to automatically allow, redact, pseudonymize, or block requests[cite: 3, 5]."
    )

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

tab1, tab2, tab3 = st.tabs(["🚀 Interactive Gateway Demo", "⚙️ Editable Policy Matrix", "📊 Audit Log & Decision Metrics"])

with tab1:
    col_scenario, _ = st.columns([2, 1])
    with col_scenario:
        selected_demo = st.selectbox("🎯 **Quick Pitch Scenario Selector:**", list(DEMO_SCENARIOS.keys()))

    # Load scenario defaults if chosen
    default_text = "Type or paste your text here..."
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

    c_input, c_env = st.columns([3, 2], gap="large")

    with c_input:
        st.markdown("### 💬 1. Input Message or Document")
        user_text = st.text_area(
            "Paste text that you want to send through the AI gateway:",
            value=default_text,
            height=150
        )
        
        run_btn = st.button("🛡️ Run Through ContextGuard Gateway", type="primary", use_container_width=True)

    with c_env:
        st.markdown("### 📦 2. Context Envelope Settings")
        with st.expander("🛠️ Configure Context Parameters", expanded=True):
            role = st.selectbox("Requester Role", ["HR Manager", "Employee", "Support Agent", "Developer", "External Contractor"],
                                index=["HR Manager", "Employee", "Support Agent", "Developer", "External Contractor"].index(default_role) if default_role in ["HR Manager", "Employee", "Support Agent", "Developer", "External Contractor"] else 0)
            source = st.text_input("Data Source", value=default_source)
            dest = st.selectbox(
                "Destination Channel", 
                ["HR_PRIVATE", "INTERNAL_SUMMARY", "PUBLIC_CHANNEL", "EXTERNAL_AI_API"],
                index=["HR_PRIVATE", "INTERNAL_SUMMARY", "PUBLIC_CHANNEL", "EXTERNAL_AI_API"].index(default_dest),
                help="Where is this data heading? External APIs carry higher risk."
            )
            purpose = st.text_input("Processing Purpose", value=default_purpose)
            restore_toggle = st.checkbox("Authorised User (Restore Pseudonyms in Output Guard)", value=True)

    if run_btn:
        with st.spinner("Analyzing context, scanning layers, and evaluating privacy policy..."):
            req = GatewayRequest(
                text=user_text,
                envelope=ContextEnvelope(requester_role=role, data_source=source, destination=dest, purpose=purpose),
                authorised_to_restore=restore_toggle
            )
            res = inspect_and_process(req)

        st.divider()
        st.markdown("### 🎯 Gateway Inspection Results")

        # Metrics Row
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Sensitivity Category", res["classification"]["sensitivity_category"])
        m2.metric("Contextual Risk Level", res["classification"]["risk_level"])
        m3.metric("Policy Action Taken", res["policy_action"])
        m4.metric("Entities Flagged", len(res["detections"]))

        # Explanation Box
        st.success(f"**🧠 Why this decision was made:** {res['classification']['reason']}")

        # Deep Dive Columns
        col_res1, col_res2 = st.columns(2)
        
        with col_res1:
            st.markdown("#### 🔍 3-Layer Detection Breakdown")
            if res["detections"]:
                st.dataframe(
                    pd.DataFrame(res["detections"])[["layer", "entity_type", "text", "confidence"]],
                    use_container_width=True,
                    hide_index=True
                )
            else:
                st.info("No sensitive entities or risks detected in this text.")

        with col_res2:
            st.markdown("#### 🛡️ Secure Payload Flow")
            st.text("Prompt sent to LLM after gateway transformation:")
            st.code(res["prompt_sent_to_llm"], language="text")
            
            st.text("Output Guard & Token Vault Restoration:")
            st.code(res["output_guard"]["final_user_output"], language="text")

with tab2:
    st.subheader("⚙️ Editable Sensitivity × Context Policy Matrix")
    st.markdown("Customize how ContextGuard responds to different categories across various destinations without rewriting code[cite: 3, 5].")
    
    matrix = load_policy_matrix()
    df_matrix = pd.DataFrame(matrix).T
    edited_df = st.data_editor(df_matrix, use_container_width=True)
    
    if st.button("💾 Save Policy Matrix Changes", type="secondary"):
        save_policy_matrix(edited_df.to_dict(orient="index"))
        st.success("✅ Policy matrix successfully updated and saved!")

with tab3:
    st.subheader("📊 SQLite Audit Trail & Decision Counters")
    st.markdown("Every decision made by ContextGuard is logged with timestamps, risk levels, and explainable reasons[cite: 3, 5].")
    
    logs = fetch_audit_logs(100)
    if logs:
        df_logs = pd.DataFrame(logs)
        c_allow = (df_logs["action_taken"] == "ALLOW").sum()
        c_redact = (df_logs["action_taken"] == "REDACT").sum()
        c_pseudo = (df_logs["action_taken"] == "PSEUDONYMIZE").sum()
        c_block = (df_logs["action_taken"].isin(["BLOCK", "ESCALATE"])).sum()

        k1, k2, k3, k4 = st.columns(4)
        k1.metric("Allowed (Safe)", int(c_allow))
        k2.metric("Redacted", int(c_redact))
        k3.metric("Pseudonymized", int(c_pseudo))
        k4.metric("Blocked / Escalated", int(c_block))

        st.divider()
        st.dataframe(
            df_logs[["id", "timestamp", "requester_role", "destination", "sensitivity_category", "risk_level", "action_taken", "reason"]],
            use_container_width=True,
            hide_index=True
        )
    else:
        st.info("No audit logs found yet. Run a scenario in the first tab to generate logs!")
