"""
FILE: import_cand_data.py
Mô tả: Script tự động import hàng loạt tri thức CAND vào PostgreSQL
"""
import json
import os
import sys

ROOT_DIR = os.path.abspath(os.path.dirname(__file__))
if ROOT_DIR not in sys.path:
    sys.path.append(ROOT_DIR)

from db_manager import get_db_connection, release_db_connection

def import_knowledge_from_json(json_file_path: str = "cand_knowledge.json"):
    if not os.path.exists(json_file_path):
        print(f"❌ Không tìm thấy tệp {json_file_path}. Vui lòng tạo tệp trước.")
        return

    with open(json_file_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    print(f"⏳ Đang chuẩn bị nạp {len(data)} bản ghi vào PostgreSQL...")

    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        insert_sql = """
            INSERT INTO police_knowledge_base 
                (category, doc_title, sub_title, keywords, content, source_url)
            VALUES (%s, %s, %s, %s, %s, %s);
        """

        records = [
            (
                item.get("category", "CHUNG"),
                item.get("doc_title", ""),
                item.get("sub_title", ""),
                item.get("keywords", ""),
                item.get("content", ""),
                item.get("source_url", "https://bocongan.gov.vn")
            )
            for item in data
        ]

        cursor.executemany(insert_sql, records)
        conn.commit()
        cursor.close()
        print(f"✅ Nạp thành công {len(records)} mục tri thức CAND vào bảng police_knowledge_base!")
    except Exception as e:
        if conn:
            conn.rollback()
        print(f"❌ Lỗi nạp dữ liệu: {e}")
    finally:
        if conn:
            release_db_connection(conn)

if __name__ == "__main__":
    import_knowledge_from_json()