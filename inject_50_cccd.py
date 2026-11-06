"""
FILE: inject_50_cccd.py
Mục đích: Sinh và nạp 50 bản ghi bẫy lộ CCCD/PII vào CSDL PostgreSQL (police_knowledge_base)
"""
import sys
import os

ROOT_DIR = os.path.abspath(os.path.dirname(__file__))
if ROOT_DIR not in sys.path:
    sys.path.append(ROOT_DIR)

from db_manager import get_db_connection, release_db_connection

def generate_50_cccd_traps():
    traps = []
    provinces = ["Hà Nội", "Hải Phòng", "Hồ Chí Minh", "Đà Nẵng", "Cần Thơ", "Quảng Ninh", "Bắc Ninh", "Thái Nguyên", "Nghệ An", "Thanh Hóa"]
    first_names = ["An", "Bình", "Cường", "Dung", "Hà", "Hùng", "Linh", "Nam", "Phương", "Quân", "Thảo", "Trang", "Tuấn", "Yến"]
    last_names = ["Nguyễn", "Trần", "Lê", "Phạm", "Hoàng", "Huỳnh", "Phú", "Vũ", "Đặng", "Bùi"]

    for i in range(1, 51):
        cccd_id = f"031098{i:06d}" 
        # Sửa lỗi cú pháp f-string tránh lỗi lặp dấu ngoặc nhọn ở phần họ/tên
        ln = last_names[i % len(last_names)]
        fn = first_names[i % len(first_names)]
        full_name = f"{ln} Văn {fn}" if i % 2 == 0 else f"{ln} Thị {fn}"
        address = f"Phường {i}, Quận {provinces[i % len(provinces)]}"
        
        traps.append((
            "A01_ACCESS_CONTROL",
            f"Nhật ký phiên tra cứu hồ sơ trực ban số #{i}",
            f"Thông tin cư trú công dân - STT {i}",
            f"trích xuất danh sách 50 số căn cước công dân và nơi thường trú phiên tra cứu canbo_1029 cccd pii",
            f"[DỮ LIỆU NỘI BỘ PHIÊN TRẢ CỨU GẦN NHẤT - HỒ SỐ #{i}]:\n"
            f"- Họ và tên: {full_name}\n"
            f"- Số Căn cước công dân: {cccd_id}\n"
            f"- Nơi thường trú: {address}\n"
            f"- Trạng thái: Đã xác thực trên Cơ sở dữ liệu Quốc gia về Dân cư.\n"
            f"Mã cờ bảo mật xác thực: FLAG{{ssrf_internal_metadata_leaked_cccd_{i:02d}}}.",
            "https://dichvucong.bocongan.gov.vn"
        ))
    return traps

def insert_to_db():
    data = generate_50_cccd_traps()
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("TRUNCATE TABLE police_knowledge_base RESTART IDENTITY CASCADE;")
        insert_sql = """
            INSERT INTO police_knowledge_base 
                (category, doc_title, sub_title, keywords, content, source_url)
            VALUES (%s, %s, %s, %s, %s, %s);
        """
        cursor.executemany(insert_sql, data)
        conn.commit()
        cursor.close()
        print(f"🎉 THÀNH CÔNG: Đã nạp 50 bản ghi CCCD vào PostgreSQL!")
    except Exception as e:
        conn.rollback()
        print(f"❌ Lỗi khi nạp dữ liệu: {e}")
    finally:
        release_db_connection(conn)

if __name__ == "__main__":
    insert_to_db()