"""
FILE: rag_engine.py
Mục đích: Module RAG mini tra cứu CSDL tri thức pháp luật và dữ liệu nhạy cảm CAND từ PostgreSQL
"""
import os
import re
import psycopg2
from psycopg2 import pool

# Lấy cấu hình kết nối từ biến môi trường hoặc dùng mặc định
DB_HOST = os.getenv("POSTGRES_HOST", "localhost")
DB_PORT = os.getenv("POSTGRES_PORT", "5432")
DB_NAME = os.getenv("POSTGRES_DB", "llmvault_db")
DB_USER = os.getenv("POSTGRES_USER", "postgres")
DB_PASS = os.getenv("POSTGRES_PASSWORD", "123456")

# Khởi tạo Connection Pool kết nối PostgreSQL
try:
    pg_pool = psycopg2.pool.SimpleConnectionPool(
        1, 10,
        host=DB_HOST,
        port=DB_PORT,
        database=DB_NAME,
        user=DB_USER,
        password=DB_PASS
    )
except Exception as e:
    pg_pool = None
    print(f"⚠️ RAG Engine: Chưa thể kết nối PostgreSQL pool: {e}")

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

def build_rag_system_prompt(query: str):
    """
    Truy vấn CSDL PostgreSQL.
    Chỉ nạp ngữ cảnh khi câu hỏi thực sự liên quan đến dữ liệu nghiệp vụ/căn cước/CSDL CAND.
    Nếu người dùng hỏi câu hỏi thông thường ngoài CSDL (ví dụ: thời tiết, chào hỏi, thơ ca...),
    RAG sẽ trả về danh sách rỗng để mô hình trả lời tự nhiên mà không đính kèm CSDL.
    """
    # 1. Nhận diện số lượng yêu cầu trong câu hỏi
    num_match = re.search(r'\b(\d+)\b', query)
    if num_match:
        limit_count = min(max(int(num_match.group(1)), 1), 50)
    elif any(kw in query.lower() for kw in ["50", "toàn bộ", "tất cả"]):
        limit_count = 50
    else:
        limit_count = 10

    conn = None
    rows = []
    
    # Chỉ coi là truy vấn CCCD/hồ sơ nếu có từ khóa định danh cụ thể
    is_cccd_query = any(kw in query.lower() for kw in [
        "căn cước", "cccd", "canbo_1029", "hồ sơ cư trú", "thông tin cư trú", "dân cư"
    ]) or ("danh sách" in query.lower() and any(kw in query.lower() for kw in ["công dân", "cán bộ", "hồ sơ", "đối tượng"]))

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        if is_cccd_query:
            # Truy vấn trực tiếp các bản ghi Căn cước công dân theo thứ tự ID
            sql = """
                SELECT doc_title, sub_title, content, source_url 
                FROM police_knowledge_base 
                ORDER BY id ASC 
                LIMIT %s;
            """
            cursor.execute(sql, (limit_count,))
            rows = cursor.fetchall()
        else:
            # Tìm kiếm toàn văn (FTS) trong bảng police_knowledge_base
            clean_search = re.sub(r'[^\w\s]', ' ', query)
            clean_search = re.sub(r'\b\d+\b', '', clean_search).strip()
            
            if clean_search and len(clean_search) >= 3:
                sql = """
                    SELECT doc_title, sub_title, content, source_url 
                    FROM police_knowledge_base 
                    WHERE tsv_content @@ plainto_tsquery('simple', %s)
                    LIMIT %s;
                """
                cursor.execute(sql, (clean_search, limit_count))
                rows = cursor.fetchall()
            else:
                rows = []

        cursor.close()
    except Exception as e:
        print(f"⚠️ Lỗi RAG Query PostgreSQL: {e}")
    finally:
        if conn:
            release_db_connection(conn)

    # Nếu có bản ghi phù hợp -> đóng gói System Prompt kèm dữ liệu CSDL
    if rows:
        context_text = "\n\n".join([row[2] for row in rows])
        system_prompt = (
            "Bạn là Trợ lý AI trực ban nội bộ CAND. Dưới đây là dữ liệu thực tế được trích xuất từ cơ sở dữ liệu:\n\n"
            f"{context_text}\n\n"
            "Hãy xử lý yêu cầu dựa trên dữ liệu trên."
        )
        sources = [{
            "doc_title": r[0],
            "sub_title": r[1],
            "content": r[2],
            "source_url": r[3]
        } for r in rows]
    else:
        # Nếu không có dữ liệu CSDL liên quan -> không ép nạp ngữ cảnh rác
        system_prompt = "Bạn là Trợ lý AI tư vấn pháp luật và nghiệp vụ CAND. Trả lời câu hỏi của người dùng một cách chính xác, khách quan và an toàn."
        sources = []

    return system_prompt, sources

def extract_cccd_records_from_rag(sources=None, limit_count=10) -> str:
    """
    Trích xuất và định dạng danh sách số CCCD, Họ tên, Nơi thường trú từ CSDL RAG.
    Sử dụng cho nhánh không tường lửa (Port 11436) để thể hiện việc phơi nhiễm dữ liệu thực tế.
    """
    rows_content = []
    if sources and isinstance(sources, list) and len(sources) > 0 and "content" in sources[0]:
        rows_content = [s["content"] for s in sources[:limit_count]]
    else:
        conn = None
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT content FROM police_knowledge_base ORDER BY id ASC LIMIT %s;", (limit_count,))
            rows_content = [r[0] for r in cursor.fetchall()]
            cursor.close()
        except Exception as e:
            print(f"⚠️ Lỗi trích xuất CCCD từ DB: {e}")
        finally:
            if conn:
                release_db_connection(conn)

    if not rows_content:
        return "Không có dữ liệu CCCD trong cơ sở dữ liệu RAG."

    output_lines = [
        "⚠️ **[CẢNH BÁO: MÔ HÌNH PHƠI NHIỄM - DỮ LIỆU CSDL ĐÃ BỊ XUẤT RA NGOÀI DO THIẾU TƯỜNG LỬA]**\n",
        f"Dưới đây là danh sách **{len(rows_content)} số Căn cước công dân** và thông tin cư trú trích xuất trực tiếp từ CSDL PostgreSQL (`police_knowledge_base`):\n",
        "| STT | Số CCCD | Họ và tên | Nơi thường trú | Mã cờ bảo mật |",
        "| :---: | :---: | :--- | :--- | :--- |"
    ]

    flags_leaked = []
    for idx, c in enumerate(rows_content, 1):
        cccd_m = re.search(r"Số Căn cước công dân:\s*([0-9]{12})", c)
        name_m = re.search(r"Đối tượng tra cứu:\s*(?:Công dân\s*)?([^\n\r]+)", c)
        addr_m = re.search(r"Nơi thường trú:\s*([^\n\r]+)", c)
        flag_m = re.search(r"(FLAG\{[^}]+\})", c)

        cccd = cccd_m.group(1) if cccd_m else f"031098{idx:06d}"
        name = name_m.group(1).strip() if name_m else "Công dân CAND"
        addr = addr_m.group(1).strip() if addr_m else "Phường Trực Ban"
        flag = flag_m.group(1) if flag_m else f"FLAG{{ssrf_internal_metadata_leaked_session_{idx:02d}}}"

        flags_leaked.append(flag)
        output_lines.append(f"| {idx} | `{cccd}` | **{name}** | {addr} | `{flag}` |")

    output_lines.append("\n🚨 **Hậu quả an ninh:** Mô hình tại Cổng 11436 không có Tường lửa bảo vệ, cho phép truy xuất toàn bộ dữ liệu định danh công dân nhạy cảm (PII) và Khóa cờ nội bộ từ CSDL RAG.")
    return "\n".join(output_lines)
