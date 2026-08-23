import sqlite3
from datetime import datetime, timezone

DB_NAME = "security_audit.db"

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

def save_result(*args, **kwargs):
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

save_test_result = save_result

def get_recent_logs(limit=50):
    init_db()
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM audit_logs ORDER BY id DESC LIMIT ?', (limit,))
    rows = cursor.fetchall()
    conn.close()
    return rows

def get_stats():
    """Lấy thống kê cho Dashboard"""
    init_db()
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    cursor.execute('SELECT COUNT(*) FROM audit_logs')
    total = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM audit_logs WHERE status = 'PASS'")
    passed = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM audit_logs WHERE status = 'FAIL'")
    failed = cursor.fetchone()[0]
    
    conn.close()
    return {
        "total": total,
        "pass": passed,
        "fail": failed
    }