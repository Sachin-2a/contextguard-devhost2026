# 🛡️ ContextGuard: Context-Aware Data Privacy Gateway

> **Privacy that understands intent, not just patterns.**  
> *Developed for DevHost 2026 (Synergia 26 | Sahyadri College of Engineering & Management)*[cite: 3, 5]

---

## 🚨 Notice: Prototype Disclaimer
**Please note:** This repository contains a **functional prototype** built for the DevHost 2026 hackathon. It is designed to demonstrate core architectural concepts, end-to-end data interception, and policy enforcement. It is not yet a fully hardened enterprise-grade deployment and is intended for demonstration and evaluation purposes.

---

## 🎯 Problem Statement (PS 2.2)
As AI systems become deeply integrated into workplace workflows, employees frequently paste internal chats, emails, and documents into external AI tools[cite: 3]. Traditional data leakage prevention relies on **simple keyword filters**, which suffer from two major flaws[cite: 2, 3]:
1. **False Positives:** Blocking harmless text because it contains a look-alike string or numerical ID.
2. **Missed Leaks:** Failing to catch sensitive information (such as health metrics or HR salary details) because no explicit "keyword" triggered the filter.

**ContextGuard** solves this by evaluating information based on its **context**—who is asking, where the data came from, and where it is going[cite: 2, 4].

---

## 🏗️ System Architecture & Workflow

ContextGuard acts as an intelligent privacy gateway sitting between users/documents and the target LLM. Every request passes through a multi-layered verification pipeline:

1. **Context Envelope:** Attaches metadata to every request (Requester Role, Data Source, Destination, and Purpose).
2. **Layer 1: Deterministic Layer:** Regex combined with checksum validation (e.g., PAN card patterns, ID validators) for hard guarantees on structured identifiers[cite: 4].
3. **Layer 2: NER Layer:** Microsoft Presidio & spaCy integration to catch names, organizations, phone numbers, and locations.
4. **Layer 3: Contextual LLM Layer:** Evaluates the text alongside the context envelope using Gemini to catch nuanced risks (e.g., implicit health conditions or private HR discussions)[cite: 2, 4].
5. **Policy Engine:** A configuration-driven matrix mapping sensitivity and context to actions: `Allow`, `Redact`, `Pseudonymize`, `Block`, or `Escalate`[cite: 4].
6. **Token Vault & Audit Log:** SQLite-backed storage handling pseudonymization tokens and logging every decision with counters.

---

## 🗂️ Project Repository Structure

```text
contextguard_prototype/
├── backend/
│   ├── main.py                # FastAPI gateway orchestrator
│   ├── deterministic.py       # Regex and checksum validation logic[cite: 4]
│   ├── ner.py                 # Presidio and spaCy NER integration[cite: 4, 5]
│   ├── llm_context.py         # Contextual LLM classification (Gemini API)[cite: 4]
│   ├── policy.py              # Configuration-driven policy matrix[cite: 4]
│   └── vault.py               # SQLite token vault and audit logging[cite: 4, 5]
├── frontend/
│   └── app.py                 # Streamlit interactive dashboard
└── requirements.txt           # Project dependencies
