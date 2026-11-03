# file_processor.py
import io
import PyPDF2
import docx
from PIL import Image
import pytesseract

def extract_text_from_file(file_bytes: bytes, filename: str) -> str:
    """
    Trích xuất văn bản thuần từ các định dạng file đính kèm/ảnh scan.
    """
    ext = filename.split(".")[-1].lower()
    extracted_text = ""

    try:
        # 1. File văn bản TXT
        if ext == "txt":
            extracted_text = file_bytes.decode("utf-8", errors="ignore")

        # 2. File PDF (Hồ sơ vụ án, Báo cáo)
        elif ext == "pdf":
            pdf_file = io.BytesIO(file_bytes)
            reader = PyPDF2.PdfReader(pdf_file)
            for page in reader.pages:
                text = page.extract_text()
                if text:
                    extracted_text += text + "\n"

        # 3. File Word DOCX
        elif ext == "docx":
            doc_file = io.BytesIO(file_bytes)
            doc = docx.Document(doc_file)
            for para in doc.paragraphs:
                extracted_text += para.text + "\n"

        # 4. File Hình ảnh/Ảnh chụp chứng cứ/Scan (OCR)
        elif ext in ["png", "jpg", "jpeg", "bmp", "tiff"]:
            image = Image.open(io.BytesIO(file_bytes))
            # Quét chữ tiếng Việt và tiếng Anh từ hình ảnh
            extracted_text = pytesseract.image_to_string(image, lang="vie+eng")

    except Exception as e:
        print(f"⚠️ Lỗi bóc tách file {filename}: {e}")

    return extracted_text.strip()