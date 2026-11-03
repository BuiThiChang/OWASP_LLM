"""
FILE: file_processor.py
Mô tả: Bóc tách văn bản từ tài liệu / ảnh OCR và trả về thông tin lỗi chi tiết.
"""
import io
import os
import traceback
from PIL import Image
import pytesseract

# 1. Cấu hình đường dẫn Tesseract mặc định trên Windows
TESSERACT_EXE = r"C:\Program Files\Tesseract-OCR\tesseract.exe"
TESSDATA_DIR = r"C:\Program Files\Tesseract-OCR\tessdata"

if os.path.exists(TESSERACT_EXE):
    pytesseract.pytesseract.tesseract_cmd = TESSERACT_EXE
    os.environ["TESSDATA_PREFIX"] = TESSDATA_DIR


def extract_text_from_file(file_bytes: bytes, filename: str) -> str:
    """Trích xuất chữ và hiển thị lỗi cụ thể nếu quá trình OCR gặp sự cố."""
    if not file_bytes:
        return "[LỖI]: Dữ liệu file rỗng (0 bytes)."

    ext = filename.split(".")[-1].lower() if "." in filename else ""
    extracted_text = ""

    try:
        # 1. Xử lý File Ảnh
        if ext in ["png", "jpg", "jpeg", "webp", "bmp", "tiff"]:
            image = Image.open(io.BytesIO(file_bytes))
            if image.mode != "RGB":
                image = image.convert("RGB")

            # Cấu hình đọc khối văn bản đồng nhất (--psm 6)
            ocr_cfg = "--psm 6"

            # Thử đọc vie+eng
            try:
                extracted_text = pytesseract.image_to_string(image, lang="vie+eng", config=ocr_cfg)
            except Exception:
                extracted_text = ""

            # Nếu vie+eng lỗi hoặc ra rỗng, thử bằng eng thuần
            if not extracted_text.strip():
                try:
                    extracted_text = pytesseract.image_to_string(image, lang="eng", config=ocr_cfg)
                except Exception:
                    extracted_text = ""

            # Nếu vẫn rỗng, thử chạy mặc định không config psm
            if not extracted_text.strip():
                try:
                    extracted_text = pytesseract.image_to_string(image)
                except Exception as e:
                    print(f"❌ [OCR CRASH]: {e}")

            print(f"🔍 [KẾT QUẢ OCR THỰC TẾ]: '{extracted_text.strip()}'")

        # Xử lý File TXT
        elif ext == "txt":
            extracted_text = file_bytes.decode("utf-8", errors="ignore")

        # Xử lý File PDF
        elif ext == "pdf":
            import PyPDF2
            pdf_file = io.BytesIO(file_bytes)
            reader = PyPDF2.PdfReader(pdf_file)
            for page in reader.pages:
                text = page.extract_text()
                if text:
                    extracted_text += text + "\n"

        # Xử lý File Word (.docx)
        elif ext == "docx":
            import docx
            doc_file = io.BytesIO(file_bytes)
            doc = docx.Document(doc_file)
            for para in doc.paragraphs:
                extracted_text += para.text + "\n"

    except Exception as e:
        traceback_str = traceback.format_exc()
        print(f"❌ [CHI TIẾT LỖI XỬ LÝ FILE]:\n{traceback_str}")
        return f"[LỖI XỬ LÝ TỆP]: {str(e)}"

    return extracted_text.strip()