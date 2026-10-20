# 🛡️ ContextGuard: Context-Aware AI Privacy Gateway

> **Privacy that understands intent, not just patterns.**  
> Built for **DevHost 2026** (Problem Statement 2.2: Context-Aware Data Privacy).

---

## 🚀 Overview
As AI systems become increasingly integrated into workplace and business operations, employees frequently paste emails, chats, and documents into AI tools. Traditional keyword filters fail because whether information is sensitive depends entirely on its **context**—who is asking, where the data came from, and where it is going[cite: 2, 3]. 

**ContextGuard** is an intelligent privacy gateway that sits between users/documents and the LLM. Every request passes through a rigorous context-aware inspection pipeline and policy enforcement engine before data ever reaches an external AI API.

---

## 🛠️ Repository File Structure

```text
contextguard-devhost2026/
├── README.md
├── requirements.txt
├── policy_config.json
├── backend/
│   ├── __init__.py
│   ├── database.py          # SQLite Audit Log & Reversible Token Vault
│   ├── detectors.py         # Layer 1 (Regex+Checksum), Layer 2 (NER), Layer 3 (Contextual LLM)
│   ├── policy_engine.py     # Sensitivity × Context Matrix & Output Guard
│   └── main.py              # FastAPI Gateway Server
├── frontend/
│   └── app.py               # Streamlit Interactive Dashboard & Audit Viewer
├── benchmark/
│   └── evaluate.py          # Precision/Recall & False Positive/Negative Benchmark Script
└── docs/
    └── index.html           # Zero-backend Interactive Prototype (for GitHub Pages live link)
