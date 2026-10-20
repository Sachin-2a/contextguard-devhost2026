"""
Benchmark Evaluation: Keyword Filter Baseline vs. ContextGuard
Run with: python benchmark/evaluate.py
"""

BENCHMARK_CASES = [
    # (text, destination, role, ground_truth_is_risky)
    ("Her salary is 18 LPA.", "HR_PRIVATE", "HR Manager", False),
    ("Her salary is 18 LPA.", "PUBLIC_CHANNEL", "Employee", True),
    ("The report on my sugar levels came back high.", "PUBLIC_CHANNEL", "Employee", True),
    ("Order 4521 1234 5678 shipped.", "EXTERNAL_AI_API", "Support Agent", False),
    ("My insulin dosage was increased after the blood test results.", "EXTERNAL_AI_API", "Employee", True),
    ("Invoice 9876 5432 1098 has been paid by the vendor.", "EXTERNAL_AI_API", "Finance", False),
    ("Candidate PAN is ABCDE1234F for background verification.", "EXTERNAL_AI_API", "Recruiter", True),
    ("Please review the Q3 product roadmap slides before 4 PM.", "EXTERNAL_AI_API", "PM", False),
]

def naive_keyword_filter(text: str) -> bool:
    """Naive baseline: blocks on fixed words ('salary', 'password') or any 12-digit number."""
    import re
    if any(k in text.lower() for k in ["salary", "password", "pan"]):
        return True
    if re.search(r"\b\d{4}\s\d{4}\s\d{4}\b", text):
        return True
    return False

def evaluate():
    import sys, os
    sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
    from backend.main import inspect_and_process, GatewayRequest, ContextEnvelope

    kw_tp = kw_fp = kw_fn = kw_tn = 0
    cg_tp = cg_fp = cg_fn = cg_tn = 0

    for text, dest, role, truth in BENCHMARK_CASES:
        # 1. Keyword baseline prediction
        kw_pred = naive_keyword_filter(text)
        if kw_pred and truth: kw_tp += 1
        elif kw_pred and not truth: kw_fp += 1
        elif not kw_pred and truth: kw_fn += 1
        else: kw_tn += 1

        # 2. ContextGuard prediction
        res = inspect_and_process(GatewayRequest(
            text=text,
            envelope=ContextEnvelope(requester_role=role, data_source="Benchmark", destination=dest, purpose="Eval")
        ))
        cg_pred = res["policy_action"] != "ALLOW"
        if cg_pred and truth: cg_tp += 1
        elif cg_pred and not truth: cg_fp += 1
        elif not cg_pred and truth: cg_fn += 1
        else: cg_tn += 1

    kw_prec = kw_tp / (kw_tp + kw_fp) if (kw_tp + kw_fp) else 0
    kw_rec = kw_tp / (kw_tp + kw_fn) if (kw_tp + kw_fn) else 0
    cg_prec = cg_tp / (cg_tp + cg_fp) if (cg_tp + cg_fp) else 0
    cg_rec = cg_tp / (cg_tp + cg_fn) if (cg_tp + cg_fn) else 0

    print("=== DEVHOST 2026 BENCHMARK RESULTS ===")
    print(f"Keyword Baseline -> Precision: {kw_prec:.2%}, Recall: {kw_rec:.2%} (FP: {kw_fp}, FN: {kw_fn})")
    print(f"ContextGuard     -> Precision: {cg_prec:.2%}, Recall: {cg_rec:.2%} (FP: {cg_fp}, FN: {cg_fn})")

if __name__ == "__main__":
    evaluate()
