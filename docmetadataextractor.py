
# pip install PyPDF2 python-docx
# How to Run Script - python script.py pdf example.pdf
# Word - python script.py docx example.docx

import sys
from docx import Document
import PyPDF2

def extract_metadata_from_pdf(pdf_path):
    try:
        with open(pdf_path, 'rb') as file:
            pdf = PyPDF2.PdfFileReader(file)
            metadata = pdf.getDocumentInfo()
            return metadata
    except Exception as e:
        print(f"Error processing {pdf_path}: {e}")
        return None

def extract_metadata_from_docx(docx_path):
    try:
        doc = Document(docx_path)
        metadata = {
            "/Title": doc.core_properties.title,
            "/Author": doc.core_properties.author,
            "/Creator": doc.core_properties.creator,
            "/Created": doc.core_properties.created,
            "/Modified": doc.core_properties.modified,
            "/Description": doc.core_properties.description,
        }
        return metadata
    except Exception as e:
        print(f"Error processing {docx_path}: {e}")
        return None

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python script_name.py <file_type> <file_path>")
        print("<file_type> should be either 'pdf' or 'docx'")
        sys.exit(1)
    
    file_type = sys.argv[1].lower()
    file_path = sys.argv[2]

    if file_type == "pdf":
        metadata = extract_metadata_from_pdf(file_path)
    elif file_type == "docx":
        metadata = extract_metadata_from_docx(file_path)
    else:
        print("Invalid file type. Supported types are 'pdf' and 'docx'.")
        sys.exit(1)

    if metadata:
        for key, value in metadata.items():
            print(f"{key}: {value}")
