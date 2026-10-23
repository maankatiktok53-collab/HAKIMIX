import os
import json

SESSION_FILE = os.path.join(os.path.dirname(__file__), "..", "data", "session.json")

def get_current_session():
    if os.path.exists(SESSION_FILE):
        try:
            with open(SESSION_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {"target": "", "notes": []}

def save_session(session_data):
    try:
        os.makedirs(os.path.dirname(SESSION_FILE), exist_ok=True)
        with open(SESSION_FILE, "w", encoding="utf-8") as f:
            json.dump(session_data, f, indent=4)
    except Exception as e:
        pass

def set_target(target_str):
    session = get_current_session()
    session["target"] = target_str.strip()
    save_session(session)
    return session["target"]

def add_note(note_str):
    session = get_current_session()
    if "notes" not in session:
        session["notes"] = []
    session["notes"].append(note_str)
    save_session(session)

def clear_session():
    session = {"target": "", "notes": []}
    save_session(session)
    return session
