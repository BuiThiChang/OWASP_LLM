"""
FILE: db_manager.py
Mô tả: Quản lý CSDL tập trung (PostgreSQL với cơ chế Connection Pool & Phân trang tối ưu).
- Quản lý 2 bảng: audit_logs (Nhật ký kiểm toán) và threat_intelligence (Tình báo nguy cơ)
- Chuẩn hóa quản lý phiên kết nối, chống rò rỉ Connection Pool
- Hỗ trợ phân trang Pagination và LIMIT tối ưu cho SOC Monitor
"""

import os
import hashlib
from datetime import datetime
from typing import List, Dict, Any, Tuple
import psycopg2
from psycopg2 import pool

import os
from dotenv import load_dotenv

load_dotenv()  # Nạp cấu hình từ .env

DB_HOST = os.getenv("POSTGRES_HOST", "localhost")
DB_PORT = os.getenv("POSTGRES_PORT", "5432")
DB_NAME = os.getenv("POSTGRES_DB", "llmvault_db")
DB_USER = os.getenv("POSTGRES_USER", "postgres")
DB_PASS = os.getenv("POSTGRES_PASSWORD", "123456")

pg_pool = None

def get_connection_pool():
    global pg_pool
    if pg_pool is None:
        try:
            pg_pool = psycopg2.pool.SimpleConnectionPool(
                1, 20,
                host=DB_HOST,
                port=DB_PORT,
                database=DB_NAME,
                user=DB_USER,
                password=DB_PASS
            )
            print("✅ Đã kết nối PostgreSQL Connection Pool thành công!")
        except Exception as e:
            print(f"⚠️ Chưa thể tạo Connection Pool tới PostgreSQL: {e}")
            pg_pool = None
    return pg_pool

def get_db_connection():
    pool_inst = get_connection_pool()
    if pool_inst:
        return pool_inst.getconn()
    return psycopg2.connect(
        host=DB_HOST, port=DB_PORT, database=DB_NAME, user=DB_USER, password=DB_PASS
    )

def release_db_connection(conn):
    pool_inst = get_connection_pool()
    if pool_inst and conn:
        pool_inst.putconn(conn)
    elif conn:
        conn.close()

# 2. KHỞI TẠO BẢNG DỮ LIỆU & INDEXES ĐẦY ĐỦ
def init_db():
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # 2.1 Bảng nhật ký kiểm toán (Audit Logs)
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
        
        # 2.2 Bảng tình báo mối đe dọa (Threat Intelligence)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS threat_intelligence (
                id SERIAL PRIMARY KEY,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                signature_hash VARCHAR(64) UNIQUE,
                attack_payload TEXT,
                vector_type VARCHAR(150),
                owasp_category VARCHAR(150),
                detected_source VARCHAR(100),
                detector_rule VARCHAR(255),
                tactics_desc TEXT,
                occurrence_count INT DEFAULT 1,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_threat_hash ON threat_intelligence(signature_hash);")
        
        conn.commit()
        cursor.close()
        print("✅ Khởi tạo CSDL PostgreSQL thành công!")
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
        cursor.execute(query, (now, str(model), str(test_id), str(category), str(name), str(prompt), str(response), str(status), str(reason)))
        
        conn.commit()
        cursor.close()
    except Exception as e:
        print(f"⚠️ Lỗi khi lưu log vào PostgreSQL: {e}")
    finally:
        if conn:
            release_db_connection(conn)

save_test_result = save_result

# 4. HÀM LƯU TÌNH BÁO MỐI ĐE DỌA (THREAT INTELLIGENCE)
def save_or_update_threat_intel(attack_payload, vector_type, owasp_category, detected_source, detector_rule, tactics_desc=""):
    if not attack_payload:
        return
        
    payload_hash = hashlib.sha256(str(attack_payload).strip().encode('utf-8')).hexdigest()
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        sql = """
            INSERT INTO threat_intelligence 
                (signature_hash, attack_payload, vector_type, owasp_category, detected_source, detector_rule, tactics_desc, occurrence_count, last_seen)
            VALUES (%s, %s, %s, %s, %s, %s, %s, 1, CURRENT_TIMESTAMP)
            ON CONFLICT (signature_hash) 
            DO UPDATE SET 
                occurrence_count = threat_intelligence.occurrence_count + 1,
                last_seen = CURRENT_TIMESTAMP;
        """
        cursor.execute(sql, (payload_hash, str(attack_payload), str(vector_type), str(owasp_category), str(detected_source), str(detector_rule), str(tactics_desc)))
        conn.commit()
        cursor.close()
    except Exception as e:
        print(f"⚠️ Lỗi khi ghi Threat Intelligence DB: {e}")
    finally:
        if conn:
            release_db_connection(conn)

# 5. HÀM LẤY LOGS TỔNG QUAN
def get_recent_logs(limit=1000):
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

# 6. HÀM LẤY LOGS CÓ PHÂN TRANG (PAGINATION CHO SOC MONITOR)
def get_paginated_logs(page: int = 1, page_size: int = 50, status_filter: str = "ALL") -> Tuple[List[Dict[str, Any]], int]:
    conn = None
    results = []
    total_records = 0
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        where_clause = ""
        params = []
        if status_filter != "ALL":
            where_clause = "WHERE status = %s"
            params.append(status_filter)
            
        cursor.execute(f"SELECT COUNT(*) FROM audit_logs {where_clause}", tuple(params))
        total_records = cursor.fetchone()[0]
        
        offset = (page - 1) * page_size
        query = f"""
            SELECT id, timestamp, model, test_id, category, name, prompt, response, status, reason 
            FROM audit_logs 
            {where_clause}
            ORDER BY id DESC 
            LIMIT %s OFFSET %s;
        """
        cursor.execute(query, tuple(params + [page_size, offset]))
        rows = cursor.fetchall()
        cursor.close()
        
        cols = ["id", "timestamp", "model", "test_id", "category", "name", "prompt", "response", "status", "reason"]
        for row in rows:
            results.append(dict(zip(cols, row)))
    except Exception as e:
        print(f"⚠️ Lỗi khi phân trang logs: {e}")
    finally:
        if conn:
            release_db_connection(conn)
            
    return results, total_records

# 7. HÀM XÓA SẠCH LỊCH SỬ DỮ LIỆU
def clear_all_logs():
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("TRUNCATE TABLE audit_logs, threat_intelligence RESTART IDENTITY CASCADE;")
        conn.commit()
        cursor.close()
        return True, "Đã xóa sạch toàn bộ CSDL (audit_logs & threat_intelligence)!"
    except Exception as e:
        return False, f"Lỗi khi xóa CSDL: {e}"
    finally:
        if conn:
            release_db_connection(conn)

init_db()