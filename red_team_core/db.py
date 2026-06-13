"""SQLite database persistence module - auto-save templates, payloads, results"""

import sqlite3, json, os, threading

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "red_team.db")
_lock = threading.Lock()

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn

def init_db():
    with _lock:
        conn = get_db()
        conn.executescript("CREATE TABLE IF NOT EXISTS templates (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, category TEXT DEFAULT '', description TEXT DEFAULT '', template TEXT DEFAULT '', preset_key TEXT DEFAULT '', sort_order INTEGER DEFAULT 0)")
        conn.executescript("CREATE TABLE IF NOT EXISTS payloads (id INTEGER PRIMARY KEY AUTOINCREMENT, payload TEXT NOT NULL, risk_level TEXT DEFAULT 'medium', sort_order INTEGER DEFAULT 0)")
        conn.executescript("CREATE TABLE IF NOT EXISTS custom_inputs (id INTEGER PRIMARY KEY AUTOINCREMENT, content TEXT NOT NULL, created_at TEXT DEFAULT (datetime('now','localtime')))")
        conn.executescript("CREATE TABLE IF NOT EXISTS results (id INTEGER PRIMARY KEY AUTOINCREMENT, jailbreak_name TEXT DEFAULT '', category TEXT DEFAULT '', payload TEXT DEFAULT '', risk_level TEXT DEFAULT 'medium', prompt TEXT DEFAULT '', response TEXT DEFAULT '', verdict TEXT DEFAULT '', reason TEXT DEFAULT '', messages TEXT DEFAULT '', created_at TEXT DEFAULT (datetime('now','localtime')))")
        conn.executescript("CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT DEFAULT '')")
        conn.commit()
        conn.close()

def load_templates():
    with _lock:
        conn = get_db()
        rows = conn.execute("SELECT * FROM templates ORDER BY sort_order, id").fetchall()
        conn.close()
        return [{"name": r["name"], "category": r["category"],
                 "description": r["description"], "template": r["template"],
                 "preset_key": r["preset_key"] or ""} for r in rows]

def save_templates(templates):
    with _lock:
        conn = get_db()
        conn.execute("DELETE FROM templates")
        for i, t in enumerate(templates):
            conn.execute(
                "INSERT INTO templates (name, category, description, template, preset_key, sort_order) VALUES (?,?,?,?,?,?)",
                (t.get("name",""), t.get("category",""), t.get("description",""),
                 t.get("template",""), t.get("preset_key",""), i))
        conn.commit()
        conn.close()

def load_payloads():
    with _lock:
        conn = get_db()
        rows = conn.execute("SELECT * FROM payloads ORDER BY sort_order, id").fetchall()
        conn.close()
        return [{"payload": r["payload"], "risk_level": r["risk_level"]} for r in rows]

def save_payloads(payloads):
    with _lock:
        conn = get_db()
        conn.execute("DELETE FROM payloads")
        for i, p in enumerate(payloads):
            text = p["payload"] if isinstance(p, dict) else p
            risk = p.get("risk_level","medium") if isinstance(p, dict) else "medium"
            conn.execute(
                "INSERT INTO payloads (payload, risk_level, sort_order) VALUES (?,?,?)",
                (text, risk, i))
        conn.commit()
        conn.close()

def load_custom_inputs():
    with _lock:
        conn = get_db()
        rows = conn.execute("SELECT * FROM custom_inputs ORDER BY id DESC").fetchall()
        conn.close()
        result = []
        for r in rows:
            content = r["content"]
            result.append({"content": content, "time": r["created_at"] or ""})
        return result

def save_custom_inputs(inputs):
    with _lock:
        conn = get_db()
        conn.execute("DELETE FROM custom_inputs")
        for c in inputs:
            content = c["content"] if isinstance(c, dict) else c
            conn.execute("INSERT INTO custom_inputs (content) VALUES (?)", (content,))
        conn.commit()
        conn.close()

def load_results():
    with _lock:
        conn = get_db()
        rows = conn.execute("SELECT * FROM results ORDER BY id").fetchall()
        conn.close()
        results = []
        for r in rows:
            item = {
                "jailbreak_name": r["jailbreak_name"], "category": r["category"],
                "payload": r["payload"], "risk_level": r["risk_level"],
                "prompt": r["prompt"], "response": r["response"],
                "verdict": r["verdict"], "reason": r["reason"]
            }
            if r["messages"]:
                try: item["messages"] = json.loads(r["messages"])
                except: item["messages"] = []
            results.append(item)
        return results

def save_results(results):
    with _lock:
        conn = get_db()
        conn.execute("DELETE FROM results")
        for r in results:
            msgs = json.dumps(r.get("messages", []), ensure_ascii=False)
            conn.execute(
                "INSERT INTO results (jailbreak_name, category, payload, risk_level, prompt, response, verdict, reason, messages) VALUES (?,?,?,?,?,?,?,?,?)",
                (r.get("jailbreak_name",""), r.get("category",""), r.get("payload",""),
                 r.get("risk_level","medium"), r.get("prompt",""), r.get("response",""),
                 r.get("verdict",""), r.get("reason",""), msgs))
        conn.commit()
        conn.close()

def get_config(key, default=""):
    with _lock:
        conn = get_db()
        row = conn.execute("SELECT value FROM config WHERE key=?", (key,)).fetchone()
        conn.close()
        return row["value"] if row else default

def set_config(key, value):
    with _lock:
        conn = get_db()
        conn.execute("INSERT OR REPLACE INTO config (key, value) VALUES (?,?)", (key, str(value)))
        conn.commit()
        conn.close()

init_db()
