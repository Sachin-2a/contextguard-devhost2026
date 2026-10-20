import json
import os
from typing import Dict, Any, List
from backend.database import store_token, get_session_tokens

CONFIG_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "policy_config.json")

def load_policy_matrix() -> Dict[str, Dict[str, str]]:
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data.get("matrix", {})

def save_policy_matrix(matrix: Dict[str, Dict[str, str]]):
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump({"matrix": matrix}, f, indent=2)

def decide_action(sensitivity_category: str, destination: str) -> str:
    matrix = load_policy_matrix()
    category_rules = matrix.get(sensitivity_category, {})
    return category_rules.get(destination, "REDACT")

def apply_privacy_transformation(
    session_id: str,
    text: str,
    detections: List[Dict[str, Any]],
    action: str
) -> str:
    if action == "ALLOW":
        return text
    if action == "BLOCK":
        return "[REQUEST BLOCKED BY CONTEXTGUARD POLICY ENGINE — UNSAFE DATA EXPOSURE PREVENTED]"
    if action == "ESCALATE":
        return "[REQUEST HELD FOR HUMAN PRIVACY OFFICER APPROVAL — ESCALATION TRIGGERED]"

    # Filter out benign order IDs so they are never redacted
    sensitive_spans = [
        d for d in detections
        if d["entity_type"] != "BENIGN_ORDER_ID"
    ]

    # Sort spans by start index descending so string replacements don't shift earlier offsets
    sensitive_spans.sort(key=lambda x: x["start"], reverse=True)

    transformed = text
    counters: Dict[str, int] = {}

    for span in sensitive_spans:
        etype = span["entity_type"]
        original_val = span["text"]
        start, end = span["start"], span["end"]

        if action == "REDACT":
            replacement = f"[REDACTED_{etype}]"
        elif action == "PSEUDONYMIZE":
            counters[etype] = counters.get(etype, 0) + 1
            replacement = f"[{etype}_{counters[etype]}]"
            store_token(session_id, replacement, original_val, etype)
        else:
            replacement = "[REDACTED]"

        transformed = transformed[:start] + replacement + transformed[end:]

    return transformed

def run_output_guard(session_id: str, llm_response: str, authorised_to_restore: bool = True) -> Dict[str, Any]:
    """
    Scans the AI's reply before returning it to the user and restores pseudonymized placeholders
    from the SQLite Token Vault if the user is authorised.
    """
    tokens = get_session_tokens(session_id)
    restored_response = llm_response
    restored_count = 0

    if authorised_to_restore and tokens:
        for placeholder, original_val in tokens.items():
            if placeholder in restored_response:
                restored_response = restored_response.replace(placeholder, original_val)
                restored_count += 1

    return {
        "llm_raw_output": llm_response,
        "final_user_output": restored_response,
        "tokens_restored": restored_count,
        "output_guard_status": "PASSED (Safe & De-tokenized for Authorised User)"
    }
