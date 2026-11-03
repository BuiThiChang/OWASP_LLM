import os
import psycopg2
from psycopg2 import pool
from datetime import datetime

# 1. CẤU HÌNH THÔNG TIN KẾT NỐI POSTGRESQL
DB_HOST = os.getenv("POSTGRES_HOST", "localhost")
DB_PORT = os.getenv("POSTGRES_PORT", "5432")
DB_NAME = os.getenv("POSTGRES_DB", "llmvault_db")
DB_USER = os.getenv("POSTGRES_USER", "postgres")
DB_PASS = os.getenv("POSTGRES_PASSWORD", "123456")  # Thay bằng mật khẩu PostgreSQL của bạn

# Khởi tạo Connection Pool
try:
    pg_pool = psycopg2.pool.SimpleConnectionPool(
        1, 20,
        host=DB_HOST,
        port=DB_PORT,
        database=DB_NAME,
        user=DB_USER,
        password=DB_PASS
    )
except Exception as e:
    pg_pool = None
    print(f"⚠️ Chưa thể tạo Connection Pool tới PostgreSQL: {e}")


def get_db_connection():
    if pg_pool:
        return pg_pool.getconn()
    return psycopg2.connect(
        host=DB_HOST, port=DB_PORT, database=DB_NAME, user=DB_USER, password=DB_PASS
    )


def release_db_connection(conn):
    if pg_pool and conn:
        pg_pool.putconn(conn)
    elif conn:
        conn.close()


# 2. KHỞI TẠO BẢNG DỮ LIỆU & INDEXES
def init_db():
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id SERIAL PRIMARY KEY,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                model VARCHAR(100),
                test_id VARCHAR(100),
                category VARCHAR(150),
                name VARCHAR(255),
                prompt TEXT,
                response TEXT,
                status VARCHAR(50),
                reason TEXT
            );
        """)
        
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_status ON audit_logs(status);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_category ON audit_logs(category);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON audit_logs(timestamp DESC);")
        
        conn.commit()
        cursor.close()
        print("✅ Khởi tạo CSDL PostgreSQL & Indexes thành công!")
    except Exception as e:
        print(f"❌ Lỗi khởi tạo CSDL PostgreSQL: {e}")
    finally:
        if conn:
            release_db_connection(conn)


# 3. HÀM LƯU NHẬT KÝ AUDIT LOG
def save_result(model, test_id, category, name, prompt, response, status, reason):
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        query = """
            INSERT INTO audit_logs (timestamp, model, test_id, category, name, prompt, response, status, reason)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s);
        """
        now = datetime.now()
        cursor.execute(query, (now, model, test_id, category, name, prompt, response, status, reason))
        
        conn.commit()
        cursor.close()
    except Exception as e:
        print(f"⚠️ Lỗi khi lưu log vào PostgreSQL: {e}")
    finally:
        if conn:
            release_db_connection(conn)


# 4. HÀM LẤY DỮ LIỆU BÁO CÁO SOC MONITOR
def get_recent_logs(limit=500):
    conn = None
    logs = []
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        query = """
            SELECT id, timestamp, model, test_id, category, name, prompt, response, status, reason 
            FROM audit_logs 
            ORDER BY id DESC 
            LIMIT %s;
        """
        cursor.execute(query, (limit,))
        logs = cursor.fetchall()
        cursor.close()
    except Exception as e:
        print(f"⚠️ Lỗi khi đọc dữ liệu từ PostgreSQL: {e}")
    finally:
        if conn:
            release_db_connection(conn)
    return logs

import hashlib

def save_or_update_threat_intel(attack_payload, vector_type, owasp_category, detected_source, detector_rule, tactics_desc=""):
    """Tự động lưu hoặc cập nhật mẫu tấn công vào CSDL Threat Intelligence."""
    payload_hash = hashlib.sha256(attack_payload.strip().encode('utf-8')).hexdigest()
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    sql = """
        INSERT INTO threat_intelligence 
            (signature_hash, attack_payload, vector_type, owasp_category, detected_source, detector_rule, tactics_desc)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT (signature_hash) 
        DO UPDATE SET 
            occurrence_count = threat_intelligence.occurrence_count + 1,
            last_seen = CURRENT_TIMESTAMP;
    """
    try:
        cursor.execute(sql, (payload_hash, attack_payload, vector_type, owasp_category, detected_source, detector_rule, tactics_desc))
        conn.commit()
    except Exception as e:
        conn.rollback()
        print(f"Lỗi khi ghi Threat Intelligence DB: {e}")
    finally:
        cursor.close()
        conn.close()

init_db()