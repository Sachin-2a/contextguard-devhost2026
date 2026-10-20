import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import streamlit as st
import pandas as pd
from backend.database import init_db, fetch_audit_logs
from backend.main import inspect_and_process, GatewayRequest, ContextEnvelope
from backend.policy_engine import load_policy_matrix, save_policy_matrix

st.set_page_config(page_title="ContextGuard | DevHost 2026", layout="wide", page_icon="🛡️")
init_db()

st.title("🛡️ ContextGuard — Context-Aware AI Privacy Gateway")
st.caption("PS 2.2 | DevHost 2026 — Privacy that understands intent, not just patterns.")

# Pre-configured Demo Scenarios from the PPT & Team Brief
DEMO_SCENARIOS = {
    "1. Salary in HR Private Thread (Allow)": {
        "text": "Her salary is 18 LPA.",
        "role": "HR Manager",
        "source": "HR Portal Message",
        "dest": "HR_PRIVATE",
        "purpose": "Internal compensation verification"
    },
    "2. Same Salary in Public/External AI (Redact/Block)": {
        "text": "Her salary is 18 LPA.",
        "role": "Team Member",
        "source": "Public Slack Channel",
        "dest": "PUBLIC_CHANNEL",
        "purpose": "Drafting team announcement"
    },
    "3. Hidden Health Detail — No Obvious Keyword (Redact)": {
        "text": "The report on my sugar levels came back high.",
        "role": "Employee",
        "source": "Shared Team Chat",
        "dest": "PUBLIC_CHANNEL",
        "purpose": "Rewriting message"
    },
    "4. E-Commerce Order ID — False Positive Guard (Allow)": {
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

tab1, tab2, tab3 = st.tabs(["⚡ Live Privacy Gateway & Demo", "⚙️ Policy Matrix Engine", "📋 SQLite Audit Log & Metrics"])

with tab1:
    st.subheader("Quick Demo Scenarios (From Pitch Deck)")
    selected_demo = st.selectbox("Load a 1-click Hackathon Pitch Scenario:", list(DEMO_SCENARIOS.keys()))
    scenario = DEMO_SCENARIOS[selected_demo]

    col_env, col_input = st.columns([1, 2])

    with col_env:
        st.markdown("### 📦 1. Context Envelope")
        role = st.selectbox("Requester Role", ["HR Manager", "Employee", "Support Agent", "Developer", "External Contractor"],
                            index=["HR Manager", "Employee", "Support Agent", "Developer", "External Contractor"].index(scenario["role"]) if scenario["role"] in ["HR Manager", "Employee", "Support Agent", "Developer", "External Contractor"] else 0)
        source = st.text_input("Data Source", value=scenario["source"])
        dest = st.selectbox("Destination Channel", ["HR_PRIVATE", "INTERNAL_SUMMARY", "PUBLIC_CHANNEL", "EXTERNAL_AI_API"],
                            index=["HR_PRIVATE", "INTERNAL_SUMMARY", "PUBLIC_CHANNEL", "EXTERNAL_AI_API"].index(scenario["dest"]))
        purpose = st.text_input("Processing Purpose", value=scenario["purpose"])
        restore_toggle = st.checkbox("Authorised User (Restore Pseudonyms in Output Guard)", value=True)

    with col_input:
        st.markdown("### 💬 2. Input Prompt / Document")
        user_text = st.text_area("Paste email, chat, or document text:", value=scenario["text"], height=130)
        run_btn = st.button("🚀 Run Through ContextGuard Gateway", type="primary", use_container_width=True)

    if run_btn:
        req = GatewayRequest(
            text=user_text,
            envelope=ContextEnvelope(requester_role=role, data_source=source, destination=dest, purpose=purpose),
            authorised_to_restore=restore_toggle
        )
        res = inspect_and_process(req)

        st.divider()
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Sensitivity Category", res["classification"]["sensitivity_category"])
        m2.metric("Contextual Risk Level", res["classification"]["risk_level"])
        m3.metric("Policy Action Taken", res["policy_action"])
        m4.metric("Entities Flagged", len(res["detections"]))

        st.info(f"**🧠 Contextual Decision Reason:** {res['classification']['reason']}")

        c1, c2 = st.columns(2)
        with c1:
            st.markdown("#### 🔍 3-Layer Detections")
            if res["detections"]:
                st.dataframe(pd.DataFrame(res["detections"])[["layer", "entity_type", "text", "confidence"]], use_container_width=True)
            else:
                st.success("No sensitive spans flagged.")

        with c2:
            st.markdown("#### 🛡️ Safe Prompt Sent to LLM")
            st.code(res["prompt_sent_to_llm"], language="text")
            st.markdown("#### 🔄 Output Guard & Token Vault Result")
            st.write("**Raw LLM Reply (Pseudonymized):**")
            st.code(res["output_guard"]["llm_raw_output"], language="text")
            st.write("**Final Output to User (After Vault Restoration):**")
            st.success(res["output_guard"]["final_user_output"])

with tab2:
    st.subheader("Editable Sensitivity × Context Policy Matrix")
    st.caption("Tune rules per organisation without changing code.")
    matrix = load_policy_matrix()
    df_matrix = pd.DataFrame(matrix).T
    edited_df = st.data_editor(df_matrix, use_container_width=True)
    if st.button("💾 Save Policy Matrix"):
        save_policy_matrix(edited_df.to_dict(orient="index"))
        st.success("Policy matrix updated!")

with tab3:
    st.subheader("SQLite Audit Trail & Decision Counters")
    logs = fetch_audit_logs(100)
    if logs:
        df_logs = pd.DataFrame(logs)
        c_allow = (df_logs["action_taken"] == "ALLOW").sum()
        c_redact = (df_logs["action_taken"] == "REDACT").sum()
        c_pseudo = (df_logs["action_taken"] == "PSEUDONYMIZE").sum()
        c_block = (df_logs["action_taken"].isin(["BLOCK", "ESCALATE"])).sum()

        k1, k2, k3, k4 = st.columns(4)
        k1.metric("Allowed (Safe/Authorised)", int(c_allow))
        k2.metric("Redacted", int(c_redact))
        k3.metric("Pseudonymized", int(c_pseudo))
        k4.metric("Blocked / Escalated", int(c_block))

        st.dataframe(
            df_logs[["id", "timestamp", "requester_role", "destination", "sensitivity_category", "risk_level", "action_taken", "reason"]],
            use_container_width=True
        )
    else:
        st.write("No audit logs recorded yet. Run a scenario in the first tab!")
