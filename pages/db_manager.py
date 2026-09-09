import sqlite3
from datetime import datetime, timezone

DB_NAME = "llmvault_audit.db"

def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            model TEXT,
            test_id TEXT,
            category TEXT,
            name TEXT,
            prompt TEXT,
            response TEXT,
            status TEXT,
            reason TEXT
        )
    ''')
    conn.commit()
    conn.close()

def save_test_result(*args, **kwargs):
    init_db()
    model = kwargs.get('model', args[0] if len(args) > 0 else 'unknown')
    test_id = kwargs.get('test_id', args[1] if len(args) > 1 else 'PROXY-LOG')
    category = kwargs.get('category', args[2] if len(args) > 2 else 'General')
    name = kwargs.get('name', args[3] if len(args) > 3 else 'Proxy Filter')
    prompt = kwargs.get('prompt', args[4] if len(args) > 4 else '')
    response = kwargs.get('response', args[5] if len(args) > 5 else '')
    status = kwargs.get('status', args[6] if len(args) > 6 else 'INFO')
    reason = kwargs.get('reason', args[7] if len(args) > 7 else '')

    now_str = datetime.now(timezone.utc).isoformat()
    
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO audit_logs (timestamp, model, test_id, category, name, prompt, response, status, reason)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (now_str, str(model), str(test_id), str(category), str(name), str(prompt), str(response), str(status), str(reason)))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"⚠️ Lỗi ghi SQLite: {e}")


def get_recent_logs(limit: int = 100):
    """Lấy danh sách log mới nhất từ CSDL audit_logs"""
    init_db()
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, timestamp, model, test_id, category, name, prompt, response, status, reason 
            FROM audit_logs 
            ORDER BY id DESC 
            LIMIT ?
        ''', (limit,))
        rows = cursor.fetchall()
        conn.close()
        return rows
    except Exception as e:
        print(f"⚠️ Lỗi truy vấn logs: {e}")
        return []

# ALIAS ĐỒNG BỘ CHO PROXY VÀ SECURITY ENGINE
save_result = save_test_result