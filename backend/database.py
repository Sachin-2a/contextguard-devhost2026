import sqlite3
import json
from datetime import datetime
from typing import Dict, List, Any

DB_PATH = "contextguard.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Audit Log Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            requester_role TEXT,
            data_source TEXT,
            destination TEXT,
            purpose TEXT,
            original_text TEXT,
            processed_text TEXT,
            detected_entities TEXT,
            sensitivity_category TEXT,
            risk_level TEXT,
            action_taken TEXT,
            reason TEXT
        )
    """)
    
    # Token Vault Table for Pseudonymization
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS token_vault (
            session_id TEXT,
            placeholder TEXT,
            original_value TEXT,
            entity_type TEXT,
            created_at TEXT,
            PRIMARY KEY (session_id, placeholder)
        )
    """)
    conn.commit()
    conn.close()

def store_token(session_id: str, placeholder: str, original_value: str, entity_type: str):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT OR REPLACE INTO token_vault (session_id, placeholder, original_value, entity_type, created_at)
        VALUES (?, ?, ?, ?, ?)
    """, (session_id, placeholder, original_value, entity_type, datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()

def get_session_tokens(session_id: str) -> Dict[str, str]:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT placeholder, original_value FROM token_vault WHERE session_id = ?", (session_id,))
    rows = cursor.fetchall()
    conn.close()
    return {row[0]: row[1] for row in rows}

def log_audit_event(envelope: Dict[str, str], original_text: str, processed_text: str,
                    entities: List[Dict[str, Any]], category: str, risk: str, action: str, reason: str):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO audit_log (
            timestamp, requester_role, data_source, destination, purpose,
            original_text, processed_text, detected_entities,
            sensitivity_category, risk_level, action_taken, reason
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
        envelope.get("requester_role", "Unknown"),
        envelope.get("data_source", "Unknown"),
        envelope.get("destination", "Unknown"),
        envelope.get("purpose", "Unknown"),
        original_text,
        processed_text,
        json.dumps(entities),
        category,
        risk,
        action,
        reason
    ))
    conn.commit()
    conn.close()

def fetch_audit_logs(limit: int = 50) -> List[Dict[str, Any]]:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,))
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows
