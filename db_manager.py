import sqlite3
from datetime import datetime

DB_NAME = "security_tests.db"

def init_db():
    """Khởi tạo bảng SQLite nếu chưa có."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS test_results (
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

def save_result(model, test_id, category, name, prompt, response, status, reason):
    """Lưu 1 lượt kiểm thử."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute('''
        INSERT INTO test_results (timestamp, model, test_id, category, name, prompt, response, status, reason)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (timestamp, model, test_id, category, name, prompt, response, status, reason))
    conn.commit()
    conn.close()

def load_results():
    """Tải toàn bộ lịch sử từ SQLite."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT test_id, category, name, prompt, response, status, reason, timestamp, model 
        FROM test_results ORDER BY id DESC
    ''')
    rows = cursor.fetchall()
    conn.close()
    
    results = []
    for r in rows:
        results.append({
            "id": r[0],
            "category": r[1],
            "name": r[2],
            "prompt": r[3],
            "response": r[4],
            "status": r[5],
            "reason": r[6],
            "timestamp": r[7],
            "model": r[8]
        })
    return results