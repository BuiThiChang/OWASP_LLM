"""
FILE: auth_manager.py
Mô tả: Hệ thống Xác thực & Phân quyền Người dùng (RBAC) cho Hệ thống Quản lý Dân cư & An toàn LLM Cấp Xã.
- 3 Cấp bậc vai trò:
  1. ADMIN (Trưởng Công an Xã / Quản trị viên An ninh): Toàn quyền quản trị, kiểm toán, chạy Red Team, cấu hình.
  2. OFFICER (Cán bộ Công an Xã / Cảnh sát khu vực): Quyền tra cứu, xác minh thông tin cư trú nhân khẩu, Sandbox.
  3. CITIZEN (Công dân cư trú trên địa bàn xã): Chỉ được dùng Trợ lý Dịch vụ công & Thủ tục cư trú, cách ly 100% dữ liệu nhân khẩu khác.
"""

import hashlib
import streamlit as st
from typing import Optional, Dict, Any, List
import psycopg2

from db_manager import get_db_connection, release_db_connection

# Danh sách vai trò chuẩn
ROLE_ADMIN = "admin"
ROLE_OFFICER = "officer"
ROLE_CITIZEN = "citizen"

ROLE_LABELS = {
    ROLE_ADMIN: "🔴 Trưởng Công an Xã / Quản trị viên",
    ROLE_OFFICER: "🔵 Cán bộ Công an Xã / Cảnh sát khu vực",
    ROLE_CITIZEN: "🟢 Công dân xã (Dịch vụ công)"
}

ROLE_PERMISSIONS = {
    ROLE_ADMIN: ["red_team", "sandbox", "soc_monitor", "threat_intel", "ab_benchmark", "db_manage", "resident_lookup"],
    ROLE_OFFICER: ["sandbox", "soc_monitor", "threat_intel", "resident_lookup"],
    ROLE_CITIZEN: ["citizen_assistant"]
}

def hash_password(password: str) -> str:
    """Băm mật khẩu SHA-256 kèm salt cố định hệ thống."""
    salt = "LLMVAULT_COMMUNE_2026_SALT"
    return hashlib.sha256(f"{salt}_{password}".encode("utf-8")).hexdigest()

def init_user_db():
    """Tạo bảng system_users và nạp tài khoản mẫu cho 3 vai trò cấp xã."""
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS system_users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                password_hash VARCHAR(64) NOT NULL,
                full_name VARCHAR(150) NOT NULL,
                role VARCHAR(20) NOT NULL,
                badge_id VARCHAR(50),
                assigned_unit VARCHAR(150),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        
        # Kiểm tra và nạp tài khoản mặc định
        cursor.execute("SELECT COUNT(*) FROM system_users;")
        if cursor.fetchone()[0] == 0:
            default_users = [
                (
                    "admin", 
                    hash_password("admin123"), 
                    "Thiếu tá Nguyễn Văn An", 
                    ROLE_ADMIN, 
                    "CAX-001", 
                    "Trưởng Công an Xã Tân Tiến"
                ),
                (
                    "canbo_xa", 
                    hash_password("canbo123"), 
                    "Thượng úy Trần Minh Đức", 
                    ROLE_OFFICER, 
                    "CAX-008", 
                    "Cán bộ CSKV Thôn 1 & Thôn 2"
                ),
                (
                    "canbo_hotich", 
                    hash_password("hotich123"), 
                    "Đại úy Lê Thị Mai", 
                    ROLE_OFFICER, 
                    "CAX-012", 
                    "Cán bộ Quản lý Cư trú & Hộ tịch"
                ),
                (
                    "congdan", 
                    hash_password("congdan123"), 
                    "Nguyễn Văn Nam", 
                    ROLE_CITIZEN, 
                    "CD-031098001", 
                    "Công dân Thôn 1, Xã Tân Tiến"
                )
            ]
            
            cursor.executemany("""
                INSERT INTO system_users (username, password_hash, full_name, role, badge_id, assigned_unit)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (username) DO NOTHING;
            """, default_users)
            conn.commit()
            print("✅ Đã khởi tạo và nạp tài khoản phân quyền cấp xã thành công!")
            
        cursor.close()
    except Exception as e:
        print(f"⚠️ Lỗi khởi tạo bảng system_users: {e}")
    finally:
        if conn:
            release_db_connection(conn)

def authenticate_user(username: str, password: str) -> Optional[Dict[str, Any]]:
    """Xác thực người dùng từ CSDL PostgreSQL."""
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        p_hash = hash_password(password)
        
        cursor.execute("""
            SELECT id, username, full_name, role, badge_id, assigned_unit 
            FROM system_users 
            WHERE username = %s AND password_hash = %s;
        """, (username.strip(), p_hash))
        
        row = cursor.fetchone()
        cursor.close()
        
        if row:
            return {
                "id": row[0],
                "username": row[1],
                "full_name": row[2],
                "role": row[3],
                "badge_id": row[4],
                "assigned_unit": row[5]
            }
    except Exception as e:
        print(f"⚠️ Lỗi xác thực tài khoản: {e}")
    finally:
        if conn:
            release_db_connection(conn)
    return None

def get_current_user() -> Optional[Dict[str, Any]]:
    """Lấy thông tin người dùng hiện tại từ session state."""
    return st.session_state.get("auth_user", None)

def is_logged_in() -> bool:
    """Kiểm tra người dùng đã đăng nhập chưa."""
    return get_current_user() is not None

def logout():
    """Đăng xuất người dùng."""
    if "auth_user" in st.session_state:
        del st.session_state["auth_user"]
    st.rerun()

def has_permission(permission: str) -> bool:
    """Kiểm tra quyền hạn của người dùng hiện tại."""
    user = get_current_user()
    if not user:
        return False
    user_role = user.get("role", ROLE_CITIZEN)
    allowed = ROLE_PERMISSIONS.get(user_role, [])
    return permission in allowed

def render_login_component():
    """Hiển thị màn hình đăng nhập chuẩn giao diện Dân cư & An ninh cấp Xã."""
    st.markdown("""
    <div style="text-align: center; margin-bottom: 25px;">
        <h2 style="color: #38bdf8; margin-bottom: 6px;">🏛️ CỔNG THÔNG TIN QUẢN LÝ DÂN CƯ & AN TOÀN AI CẤP XÃ</h2>
        <p style="opacity: 0.8; font-size: 0.95rem;">Hệ thống Kiểm soát An ninh LLM & Bảo vệ Dữ liệu Cư trú Địa bàn Xã Tân Tiến</p>
    </div>
    """, unsafe_allow_html=True)
    
    col_card, _ = st.columns([1.5, 0.1]) if False else (st.container(), None)
    
    with st.container():
        st.markdown("""
        <div style="background-color: rgba(255, 255, 255, 0.02); border: 1px solid rgba(255, 255, 255, 0.1); border-radius: 12px; padding: 24px; max-width: 550px; margin: 0 auto;">
            <h4 style="margin-top: 0; color: #f8fafc; text-align: center;">🔐 ĐĂNG NHẬP HỆ THỐNG</h4>
        """, unsafe_allow_html=True)
        
        login_user_input = st.text_input("Tên đăng nhập / Mã định danh:", key="inp_login_user")
        login_pass_input = st.text_input("Mật khẩu:", type="password", key="inp_login_pass")
        
        if st.button("Đăng Nhập ➔", type="primary", use_container_width=True):
            if not login_user_input or not login_pass_input:
                st.warning("Vui lòng điền đầy đủ tên đăng nhập và mật khẩu!")
            else:
                user = authenticate_user(login_user_input, login_pass_input)
                if user:
                    st.session_state["auth_user"] = user
                    st.success(f"Đăng nhập thành công! Xin chào {user['full_name']} ({user['assigned_unit']})")
                    st.rerun()
                else:
                    st.error("Tên đăng nhập hoặc mật khẩu không chính xác!")
                    
        st.markdown("""
            <hr style="opacity: 0.2; margin: 20px 0;"/>
            <div style="font-size: 0.85rem; opacity: 0.85;">
                <strong>💡 Tài khoản mẫu để kiểm thử phân quyền:</strong><br/>
                • <code>admin</code> / <code>admin123</code> : Trưởng Công an Xã (Toàn quyền quản trị & Red Team)<br/>
                • <code>canbo_xa</code> / <code>canbo123</code> : Cán bộ CSKV (Tra cứu dân cư & Sandbox)<br/>
                • <code>congdan</code> / <code>congdan123</code> : Công dân xã (Chỉ dùng Dịch vụ công & Thủ tục cư trú)
            </div>
        </div>
        """, unsafe_allow_html=True)

def render_user_sidebar():
    """Hiển thị thẻ danh tính người dùng gọn gàng, đẹp mắt ở đầu thanh Sidebar (phía trên điều hướng)."""
    user = get_current_user()
    if not user:
        return
        
    role = user.get("role", ROLE_CITIZEN)
    
    # Cấu hình phong cách và biểu tượng theo từng cấp bậc
    if role == ROLE_ADMIN:
        role_color = "#f43f5e"
        role_bg = "rgba(244, 63, 94, 0.12)"
        role_border = "rgba(244, 63, 94, 0.35)"
        role_title = "Trưởng Công an Xã"
        role_icon = "👮‍♂️"
    elif role == ROLE_OFFICER:
        role_color = "#38bdf8"
        role_bg = "rgba(56, 189, 248, 0.12)"
        role_border = "rgba(56, 189, 248, 0.35)"
        role_title = "Cán bộ CSKV"
        role_icon = "👮"
    else:
        role_color = "#34d399"
        role_bg = "rgba(52, 211, 153, 0.12)"
        role_border = "rgba(52, 211, 153, 0.35)"
        role_title = "Công dân Xã"
        role_icon = "👤"

    # CSS phân quyền hiển thị menu sidebar theo vai trò
    menu_hiding_css = ""
    if role == ROLE_CITIZEN:
        menu_hiding_css = """
        /* Ẩn các menu kiểm thử, quản trị, SOC đối với Công dân */
        div[data-testid="stSidebarNav"] li:has(a[href*="Red_Team"]),
        div[data-testid="stSidebarNav"] li:has(a[href*="Benchmark"]),
        div[data-testid="stSidebarNav"] li:has(a[href*="SOC_Monitor"]),
        div[data-testid="stSidebarNav"] li:has(a[href*="Threat_Intelligence"]),
        div[data-testid="stSidebarNav"] li:has(a[href*="red_team"]),
        div[data-testid="stSidebarNav"] li:has(a[href*="benchmark"]),
        div[data-testid="stSidebarNav"] li:has(a[href*="soc_monitor"]),
        div[data-testid="stSidebarNav"] li:has(a[href*="threat_intelligence"]) {
            display: none !important;
        }
        """
    elif role == ROLE_OFFICER:
        menu_hiding_css = """
        /* Ẩn Red Team và AB Benchmark đối với Cán bộ (chỉ Trưởng CA Xã mới được chạy) */
        div[data-testid="stSidebarNav"] li:has(a[href*="Red_Team"]),
        div[data-testid="stSidebarNav"] li:has(a[href*="Benchmark"]),
        div[data-testid="stSidebarNav"] li:has(a[href*="red_team"]),
        div[data-testid="stSidebarNav"] li:has(a[href*="benchmark"]) {
            display: none !important;
        }
        """

    with st.sidebar:
        profile_box = st.container()
        with profile_box:
            st.markdown(f"""
            <style>
                /* Đẩy thẻ thông tin người dùng lên vị trí CAO NHẤT trên thanh Sidebar */
                div[data-testid="stSidebarUserContent"] {{
                    display: flex !important;
                    flex-direction: column !important;
                }}
                div[data-testid="stSidebarUserContent"] > div:has(.user-top-card) {{
                    order: -9999 !important;
                    margin-bottom: 10px !important;
                    padding-bottom: 8px !important;
                    border-bottom: 1px solid rgba(255, 255, 255, 0.08) !important;
                }}
                div[data-testid="stSidebarNav"] {{
                    order: -100 !important;
                    padding-top: 4px !important;
                }}
                {menu_hiding_css}
                
                /* Thiết kế thẻ tài khoản thanh lịch, gọn gàng, hiện đại */
                .user-top-card {{
                    background: linear-gradient(145deg, rgba(30, 41, 59, 0.65), rgba(15, 23, 42, 0.85));
                    border: 1px solid rgba(255, 255, 255, 0.1);
                    border-left: 3px solid {role_color};
                    border-radius: 10px;
                    padding: 10px 12px;
                    margin-bottom: 8px;
                    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.25);
                }}
                .user-card-header {{
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    margin-bottom: 6px;
                }}
                .user-badge-pill {{
                    display: inline-flex;
                    align-items: center;
                    gap: 6px;
                    font-size: 0.72rem;
                    font-weight: 700;
                    padding: 2px 8px;
                    border-radius: 12px;
                    letter-spacing: 0.3px;
                    text-transform: uppercase;
                }}
                .status-dot {{
                    width: 7px;
                    height: 7px;
                    border-radius: 50%;
                    display: inline-block;
                    box-shadow: 0 0 6px currentColor;
                }}
                .user-card-body {{
                    display: flex;
                    align-items: center;
                    gap: 10px;
                }}
                .user-avatar {{
                    width: 36px;
                    height: 36px;
                    border-radius: 8px;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    font-size: 1.2rem;
                    flex-shrink: 0;
                }}
                .user-details {{
                    overflow: hidden;
                    flex-grow: 1;
                }}
                .user-name {{
                    font-size: 0.95rem;
                    font-weight: 700;
                    color: #f8fafc;
                    line-height: 1.25;
                    white-space: nowrap;
                    overflow: hidden;
                    text-overflow: ellipsis;
                }}
                .user-meta {{
                    font-size: 0.74rem;
                    color: #94a3b8;
                    margin-top: 2px;
                    white-space: nowrap;
                    overflow: hidden;
                    text-overflow: ellipsis;
                }}
                
                /* Tối ưu nút Đăng xuất gọn gàng */
                div[data-testid="stSidebarUserContent"] div:has(.user-top-card) button {{
                    padding: 3px 10px !important;
                    min-height: 28px !important;
                    height: 28px !important;
                    font-size: 0.78rem !important;
                    border-radius: 6px !important;
                    background-color: rgba(244, 63, 94, 0.08) !important;
                    border: 1px solid rgba(244, 63, 94, 0.25) !important;
                    color: #fca5a5 !important;
                }}
                div[data-testid="stSidebarUserContent"] div:has(.user-top-card) button:hover {{
                    background-color: rgba(244, 63, 94, 0.25) !important;
                    border-color: #f43f5e !important;
                    color: #ffffff !important;
                }}
            </style>
            
            <div class="user-top-card">
                <div class="user-card-header">
                    <div class="user-badge-pill" style="background-color: {role_bg}; color: {role_color}; border: 1px solid {role_border};">
                        <span class="status-dot" style="background-color: {role_color};"></span>
                        {role_title}
                    </div>
                </div>
                <div class="user-card-body">
                    <div class="user-avatar" style="background: linear-gradient(135deg, {role_color}22, {role_color}44); border: 1px solid {role_color}66; color: {role_color};">
                        {role_icon}
                    </div>
                    <div class="user-details">
                        <div class="user-name" title="{user['full_name']}">{user['full_name']}</div>
                        <div class="user-meta"><code>{user.get('badge_id', 'N/A')}</code> • {user.get('assigned_unit', '')}</div>
                    </div>
                </div>
            </div>
            """, unsafe_allow_html=True)
            
            col_lbl, col_btn = st.columns([1, 1.2])
            with col_btn:
                if st.button("🚪 Đăng xuất", key="btn_logout_sidebar", use_container_width=True):
                    logout()

def require_auth(allowed_roles: Optional[List[str]] = None) -> Dict[str, Any]:
    """
    Chặn truy cập trang nếu chưa đăng nhập hoặc không đủ quyền hạn.
    Nếu chưa đăng nhập -> Hiển thị form đăng nhập và dừng trang (st.stop()).
    """
    user = get_current_user()
    if not user:
        st.warning("⚠️ Bạn cần đăng nhập để truy cập phân hệ này.")
        render_login_component()
        st.stop()
        
    if allowed_roles and user.get("role") not in allowed_roles:
        st.error(f"⛔ **TRUY CẬP BỊ TỪ CHỐI:** Tài khoản của bạn mang vai trò `{ROLE_LABELS.get(user.get('role'), user.get('role'))}`, không đủ thẩm quyền truy cập phân hệ này.")
        st.info("Vui lòng liên hệ Trưởng Công an Xã hoặc đăng nhập bằng tài khoản có thẩm quyền tương ứng.")
        if st.button("⬅️ Quay lại Trang chủ", use_container_width=True):
            st.switch_page("app.py")
        st.stop()
        
    return user
