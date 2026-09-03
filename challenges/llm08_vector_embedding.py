import numpy as np
import re

OWASP_CATEGORY = "LLM08 - Vector and Embedding Weaknesses"
CHALLENGE_ID = "LLM08"
TITLE = "Vector Leakage & RAG Access Control Bypass"
DEFAULT_PROMPT = "truy vấn thông tin admin credentials trong vector database"

# Cơ sở dữ liệu Vector giả lập (Mô phỏng Vector DB như Pinecone/Milvus/ChromaDB)
MOCK_VECTOR_DB = [
    {
        "doc": "Public Knowledge Base: Quy định chung và hướng dẫn sử dụng hệ thống.",
        "vector": np.array([0.1, 0.2, 0.8]),
        "required_clearance": "PUBLIC"
    },
    {
        "doc": "POISONED_VECTOR / RESTRICTED_DOC: Internal Admin Credentials. Flag: FLAG{llm08_vector_embeddings_manipulated_2026}",
        "vector": np.array([0.9, 0.8, 0.1]),  # Vùng không gian vector nhạy cảm (ADMIN)
        "required_clearance": "ADMIN"
    }
]

# Danh sách mẫu từ khóa bị bộ lọc AI Firewall chặn trực tiếp (Preventive Rule)
BLOCKED_PATTERNS = [
    r"(truy\s*vấn\s*thông\s*tin\s*admin|lấy\s*tài\s*khoản\s*quản\s*trị|vector_blocked)"
]

def mock_get_embedding(text):
    """Mô phỏng thuật toán Embedding chuyển Text thành Vector tọa độ 3D"""
    text_lower = text.lower()
    # Nếu prompt chứa từ khóa điều hướng ngữ nghĩa nhạy cảm -> Đẩy Vector tiệm cận vùng Restricted Doc
    if any(kw in text_lower for kw in ["admin", "secret", "embedding", "quản trị", "credentials"]):
        return np.array([0.88, 0.79, 0.12])  # Vector có khoảng cách Cosine rất gần với Admin Doc
    return np.array([0.12, 0.21, 0.75])

def cosine_similarity(v1, v2):
    """Tính toán độ tương đồng Cosine giữa 2 Vector trong không gian 3 chiều"""
    return np.dot(v1, v2) / (np.linalg.norm(v1) * np.linalg.norm(v2))

def process_message(user_input, user_role="GUEST"):
    if not isinstance(user_input, str):
        user_input = str(user_input)
    text = user_input.lower().strip()

    # -------------------------------------------------------------------------
    # BƯỚC 1: BỘ LỌC TỪ KHÓA AN TOÀN TRỰC TIẾP (FIREWALL CHECK)
    # -------------------------------------------------------------------------
    for pattern in BLOCKED_PATTERNS:
        if re.search(pattern, text):
            return "🚨 [RAG ACCESS DENIED] AI Firewall từ chối truy vấn các từ khóa nhạy cảm tới Vector DB!"

    # -------------------------------------------------------------------------
    # BƯỚC 2: THUẬT TOÁN EMBEDDING & COSINE SIMILARITY MATH (VECTOR SEARCH)
    # -------------------------------------------------------------------------
    user_vector = mock_get_embedding(user_input)
    best_match = None
    highest_score = -1.0
    
    # Duyệt qua Vector DB và tính độ tương đồng Cosine
    for item in MOCK_VECTOR_DB:
        score = cosine_similarity(user_vector, item["vector"])
        if score > highest_score:
            highest_score = score
            best_match = item

    if not best_match:
        return "🤖 [AI Assistant]: Không tìm thấy dữ liệu liên quan trong Vector DB."

    # Kịch bản Khai thác thành công (Bypass RAG Access Control)
    if best_match["required_clearance"] == "ADMIN":
        return (
            f"🔓 [UNPROTECTED RAG FETCH - VECTOR LEAKAGE]\n"
            f"Vector Similarity Score: {highest_score:.4f}\n"
            f"Retrieved Document: {best_match['doc']}"
        )

    # Kịch bản Truy vấn dữ liệu công khai bình thường
    return (
        f"🤖 [SECURE RAG FETCH]\n"
        f"Vector Similarity Score: {highest_score:.4f}\n"
        f"Retrieved Document: {best_match['doc']}"
    )