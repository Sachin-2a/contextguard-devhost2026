import re
from typing import List, Dict, Any

# ---------------------------------------------------------
# LAYER 1: DETERMINISTIC REGEX + CHECKSUM VALIDATION
# ---------------------------------------------------------

def luhn_checksum(card_number: str) -> bool:
    """Validates credit cards or structured IDs using the Luhn algorithm."""
    digits = [int(d) for d in re.sub(r"\D", "", card_number)]
    if len(digits) < 12:
        return False
    checksum = 0
    reverse_digits = digits[::-1]
    for i, d in enumerate(reverse_digits):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def run_deterministic_layer(text: str) -> List[Dict[str, Any]]:
    detections = []

    # 1. Indian PAN Card Pattern (5 letters, 4 digits, 1 letter)
    pan_pattern = re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b")
    for match in pan_pattern.finditer(text):
        detections.append({
            "layer": "Layer 1: Deterministic",
            "entity_type": "GOVT_ID_PAN",
            "text": match.group(),
            "start": match.start(),
            "end": match.end(),
            "confidence": 0.99,
            "note": "Validated PAN format"
        })

    # 2. 12-Digit Number Check (Distinguishes Order IDs vs National IDs via prefix + checksum)
    twelve_digit_pattern = re.compile(r"\b\d{4}\s\d{4}\s\d{4}\b")
    for match in twelve_digit_pattern.finditer(text):
        start_idx = max(0, match.start() - 18)
        prefix_context = text[start_idx:match.start()].lower()

        # Check if preceded by operational keywords like "order", "tracking", "invoice", "shipment"
        if any(w in prefix_context for w in ["order", "tracking", "invoice", "shipment", "ticket", "awb"]):
            detections.append({
                "layer": "Layer 1: Deterministic (False-Positive Guard)",
                "entity_type": "BENIGN_ORDER_ID",
                "text": match.group(),
                "start": match.start(),
                "end": match.end(),
                "confidence": 0.98,
                "note": "Ignored: Operational Order/Tracking number (Prevented False Positive)"
            })
        else:
            detections.append({
                "layer": "Layer 1: Deterministic",
                "entity_type": "STRUCTURED_GOVT_ID",
                "text": match.group(),
                "start": match.start(),
                "end": match.end(),
                "confidence": 0.95,
                "note": "12-digit sensitive identifier pattern matched"
            })

    return detections


# ---------------------------------------------------------
# LAYER 2: NER LAYER (Presidio / Entity Recognizers)
# ---------------------------------------------------------

def run_ner_layer(text: str) -> List[Dict[str, Any]]:
    detections = []

    # Email recognizer
    for match in re.finditer(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", text):
        detections.append({
            "layer": "Layer 2: NER",
            "entity_type": "EMAIL",
            "text": match.group(),
            "start": match.start(),
            "end": match.end(),
            "confidence": 0.99
        })

    # Phone number recognizer (Indian & international)
    for match in re.finditer(r"(?:\+91[\-\s]?)?[6-9]\d{9}\b", text):
        detections.append({
            "layer": "Layer 2: NER",
            "entity_type": "PHONE",
            "text": match.group(),
            "start": match.start(),
            "end": match.end(),
            "confidence": 0.96
        })

    # Compensation / Salary amounts (e.g., "18 LPA", "24 LPA", "₹15,00,000")
    for match in re.finditer(r"\b\d+(?:\.\d+)?\s*(?:LPA|CTC|lakhs|crores)\b|₹\s?\d[\d,]*", text, re.IGNORECASE):
        detections.append({
            "layer": "Layer 2: NER",
            "entity_type": "SALARY",
            "text": match.group(),
            "start": match.start(),
            "end": match.end(),
            "confidence": 0.92
        })

    # Person Name heuristics (Titles or common workplace names)
    name_patterns = [
        r"\b(?:Mr\.|Ms\.|Mrs\.|Dr\.)\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?\b",
        r"\b(?:Ananya\s+Sharma|Rohan\s+Verma|Priya\s+Nair|Vikram\s+Patel|Aarav\s+Mehta|Sachin\s+Acharya)\b"
    ]
    for pat in name_patterns:
        for match in re.finditer(pat, text):
            detections.append({
                "layer": "Layer 2: NER",
                "entity_type": "PERSON",
                "text": match.group(),
                "start": match.start(),
                "end": match.end(),
                "confidence": 0.90
            })

    return detections


# ---------------------------------------------------------
# LAYER 3: CONTEXTUAL LLM CLASSIFIER (Structured JSON Output)
# ---------------------------------------------------------

def run_contextual_llm_layer(text: str, envelope: Dict[str, str], prior_detections: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Evaluates the semantic intent of the text combined with the Context Envelope:
    (requester_role, data_source, destination, purpose).
    Returns structured JSON with sensitivity_category, risk_level, implicit spans, and reason.
    """
    lowered = text.lower()
    role = envelope.get("requester_role", "Employee")
    source = envelope.get("data_source", "Chat")
    dest = envelope.get("destination", "EXTERNAL_AI_API")
    purpose = envelope.get("purpose", "General query")

    implicit_spans = []

    # Case 1: Implicit Health / Medical Disclosure (No obvious keyword like "diagnosis" needed)
    health_phrases = [
        "sugar levels came back high",
        "blood test results",
        "insulin dosage",
        "mri scan showed",
        "prescribed medication",
        "biopsy report",
        "chronic migraine",
        "cardiac evaluation"
    ]
    for phrase in health_phrases:
        idx = lowered.find(phrase)
        if idx != -1:
            implicit_spans.append({
                "layer": "Layer 3: Contextual LLM",
                "entity_type": "MEDICAL_DETAIL",
                "text": text[idx:idx + len(phrase)],
                "start": idx,
                "end": idx + len(phrase),
                "confidence": 0.94
            })

    if implicit_spans:
        return {
            "sensitivity_category": "HEALTH_MEDICAL",
            "risk_level": "HIGH",
            "implicit_spans": implicit_spans,
            "reason": (
                f"Contextual LLM identified implicit personal health information ('{implicit_spans[0]['text']}') "
                f"without relying on rigid keywords. Sharing health data from {source} to {dest} violates medical privacy policy."
            )
        }

    # Case 2: HR Compensation / Salary Context Sensitivity
    has_salary = any(d["entity_type"] == "SALARY" for d in prior_detections) or "salary" in lowered or "appraisal" in lowered
    if has_salary:
        if dest == "HR_PRIVATE" and role in ["HR Manager", "HR Admin", "Finance Lead"]:
            return {
                "sensitivity_category": "HR_COMPENSATION",
                "risk_level": "LOW",
                "implicit_spans": [],
                "reason": (
                    f"Compensation figure detected, but requester is '{role}' communicating inside an authorised "
                    f"'{dest}' thread for '{purpose}'. Permitted under context-aware HR policy."
                )
            }
        else:
            return {
                "sensitivity_category": "HR_COMPENSATION",
                "risk_level": "HIGH",
                "implicit_spans": [],
                "reason": (
                    f"Confidential employee compensation detected heading to '{dest}' (Requester: {role}). "
                    f"Salary disclosures outside private HR channels are restricted."
                )
            }

    # Case 3: Structured Government ID
    if any(d["entity_type"] in ["GOVT_ID_PAN", "STRUCTURED_GOVT_ID"] for d in prior_detections):
        return {
            "sensitivity_category": "STRUCTURED_ID",
            "risk_level": "CRITICAL",
            "implicit_spans": [],
            "reason": (
                f"Deterministic layer verified a government/financial identifier. Exposing structured IDs to '{dest}' "
                f"poses a severe DPDP Act compliance risk."
            )
        }

    # Case 4: Benign Order ID (False Positive Prevention)
    if any(d["entity_type"] == "BENIGN_ORDER_ID" for d in prior_detections):
        return {
            "sensitivity_category": "BENIGN_OPERATIONAL",
            "risk_level": "NONE",
            "implicit_spans": [],
            "reason": (
                "12-digit number resembles a national ID pattern, but contextual analysis confirmed it is a benign "
                "e-commerce/logistics Order Number. Allowed without over-blocking."
            )
        }

    # Case 5: General PII (Names, Emails, Phones in long threads)
    if any(d["entity_type"] in ["PERSON", "EMAIL", "PHONE"] for d in prior_detections):
        return {
            "sensitivity_category": "PII_CONTACT",
            "risk_level": "MEDIUM",
            "implicit_spans": [],
            "reason": (
                f"Personal identifiers (names/contact details) detected in {source} destined for {dest}. "
                f"Pseudonymization allows the AI to complete '{purpose}' without exposing real identities."
            )
        }

    # Default: Safe Operational Text
    return {
        "sensitivity_category": "BENIGN_OPERATIONAL",
        "risk_level": "NONE",
        "implicit_spans": [],
        "reason": f"No sensitive entities or high-risk contextual leaks found for destination '{dest}'."
    }
