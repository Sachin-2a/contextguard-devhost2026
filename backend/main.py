import uuid
from fastapi import FastAPI
from pydantic import BaseModel
from typing import Dict, Any
from backend.database import init_db, log_audit_event, fetch_audit_logs
from backend.detectors import run_deterministic_layer, run_ner_layer, run_contextual_llm_layer
from backend.policy_engine import (
    decide_action,
    apply_privacy_transformation,
    run_output_guard,
    load_policy_matrix,
    save_policy_matrix
)

app = FastAPI(title="ContextGuard Privacy Gateway API", version="1.0.0")

# Initialize SQLite tables on startup
init_db()

class ContextEnvelope(BaseModel):
    requester_role: str = "HR Manager"
    data_source: str = "Internal Email Thread"
    destination: str = "EXTERNAL_AI_API"  # HR_PRIVATE, INTERNAL_SUMMARY, PUBLIC_CHANNEL, EXTERNAL_AI_API
    purpose: str = "Summarize thread"

class GatewayRequest(BaseModel):
    text: str
    envelope: ContextEnvelope
    authorised_to_restore: bool = True

@app.post("/api/inspect")
def inspect_and_process(req: GatewayRequest) -> Dict[str, Any]:
    session_id = str(uuid.uuid4())[:8]
    env_dict = req.envelope.model_dump()

    # 1. Layer 1: Deterministic Regex + Checksum
    l1_detections = run_deterministic_layer(req.text)

    # 2. Layer 2: NER Layer
    l2_detections = run_ner_layer(req.text)

    # 3. Layer 3: Contextual LLM Layer
    combined_prior = l1_detections + l2_detections
    l3_result = run_contextual_llm_layer(req.text, env_dict, combined_prior)

    all_detections = combined_prior + l3_result.get("implicit_spans", [])
    category = l3_result["sensitivity_category"]
    risk_level = l3_result["risk_level"]
    reason = l3_result["reason"]

    # 4. Policy Engine Decision
    action = decide_action(category, req.envelope.destination)

    # 5. Apply Transformation (Allow / Redact / Pseudonymize / Block / Escalate)
    processed_prompt = apply_privacy_transformation(session_id, req.text, all_detections, action)

    # 6. Simulated Downstream LLM Processing + Output Guard
    if action in ["BLOCK", "ESCALATE"]:
        simulated_llm_reply = "Downstream LLM call was prevented by ContextGuard Policy Engine."
    else:
        simulated_llm_reply = (
            f"AI Summary ({req.envelope.purpose}): Processed input -> \"{processed_prompt}\". "
            f"Key action items have been extracted safely."
        )

    output_guard_result = run_output_guard(
        session_id=session_id,
        llm_response=simulated_llm_reply,
        authorised_to_restore=(req.authorised_to_restore and action == "PSEUDONYMIZE")
    )

    # 7. Log to SQLite Audit Trail
    log_audit_event(
        envelope=env_dict,
        original_text=req.text,
        processed_text=processed_prompt,
        entities=all_detections,
        category=category,
        risk=risk_level,
        action=action,
        reason=reason
    )

    return {
        "session_id": session_id,
        "envelope": env_dict,
        "detections": all_detections,
        "classification": {
            "sensitivity_category": category,
            "risk_level": risk_level,
            "reason": reason
        },
        "policy_action": action,
        "prompt_sent_to_llm": processed_prompt,
        "output_guard": output_guard_result
    }

@app.get("/api/audit-logs")
def get_logs():
    return {"logs": fetch_audit_logs()}

@app.get("/api/policy")
def get_policy():
    return {"matrix": load_policy_matrix()}

@app.post("/api/policy")
def update_policy(matrix: Dict[str, Dict[str, str]]):
    save_policy_matrix(matrix)
    return {"status": "updated", "matrix": matrix}
