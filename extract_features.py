import os
import math
from collections import Counter
from PyPDF2 import PdfReader
import pefile
import pandas as pd
from zipfile import ZipFile

# ---------------- Utility Functions ---------------- #
def calculate_entropy(filepath):
    """Calculate Shannon entropy of a file."""
    try:
        with open(filepath, "rb") as f:
            data = f.read()
        if not data:
            return 0
        counter = Counter(data)
        entropy = -sum((count / len(data)) * math.log2(count / len(data)) for count in counter.values())
        return entropy
    except Exception:
        return 0


def empty_features(feature_list=None, filename="unknown"):
    """Return a safe empty feature set for unknown/failed files."""
    base = {
        "filename": [filename],
        "size": [0],
        "num_pages": [0],
        "num_sections": [0],
        "num_files": [0],
        "text_length": [0],
        "word_count": [0],
        "line_count": [0],
        "has_js": [0],
        "has_suspicious_strings": [0],
        "entropy": [0],
        "is_pdf": [0],
        "is_exe": [0],
        "is_apk": [0],
        "is_txt": [0],
        "is_csv": [0],
    }
    df = pd.DataFrame(base)

    if feature_list:
        for f in feature_list:
            if f not in df.columns:
                df[f] = 0
        df = df[feature_list]

    return df


# ---------------- PDF Feature Extraction ---------------- #
def extract_pdf_features(filepath):
    try:
        reader = PdfReader(filepath)
        num_pages = len(reader.pages)
        pdf_text = ""
        for page in reader.pages:
            try:
                pdf_text += page.extract_text() or ""
            except:
                continue
        text_length = len(pdf_text)
        has_js = int("javascript" in pdf_text.lower())
        suspicious_strings = int("obj" in pdf_text.lower())
        entropy = calculate_entropy(filepath)

        features = {
            "filename": [os.path.basename(filepath)],
            "size": [os.path.getsize(filepath)],
            "num_pages": [num_pages],
            "text_length": [text_length],
            "word_count": [len(pdf_text.split())],
            "line_count": [pdf_text.count("\n") + 1],
            "num_sections": [0],
            "num_files": [0],
            "has_js": [has_js],
            "has_suspicious_strings": [suspicious_strings],
            "entropy": [entropy],
            "is_pdf": [1]
        }
        return pd.DataFrame(features)
    except Exception:
        return empty_features(filename=os.path.basename(filepath))


# ---------------- EXE Feature Extraction ---------------- #
def extract_exe_features(filepath, feature_list=None):
    try:
        pe = pefile.PE(filepath)
        section_entropies = [s.get_entropy() for s in pe.sections]
        suspicious_imports = 0
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name and b"GetProcAddress" in imp.name:
                        suspicious_imports = 1

        features = {
            "filename": [os.path.basename(filepath)],
            "size": [os.path.getsize(filepath)],
            "NumberOfSections": [len(pe.sections)],
            "SizeOfOptionalHeader": [pe.OPTIONAL_HEADER.SizeOfOptionalHeader],
            "Characteristics": [pe.FILE_HEADER.Characteristics],
            "SuspiciousImportFunctions": [suspicious_imports],
            "SectionMinEntropy": [min(section_entropies) if section_entropies else 0],
            "SectionMaxEntropy": [max(section_entropies) if section_entropies else 0],
            "entropy": [calculate_entropy(filepath)],
            "num_pages": [0],
            "num_files": [0],
            "text_length": [0],
            "word_count": [0],
            "line_count": [0],
            "has_js": [0],
            "has_suspicious_strings": [0],
            "is_exe": [1]
        }

        df = pd.DataFrame(features)

        # Align with expected features if provided
        if feature_list:
            for f in feature_list:
                if f not in df.columns:
                    df[f] = 0
            df = df[feature_list]

        return df
    except Exception:
        return empty_features(feature_list, filename=os.path.basename(filepath))


# ---------------- APK Feature Extraction ---------------- #
def extract_apk_features(filepath):
    try:
        with ZipFile(filepath, "r") as zipf:
            file_count = len(zipf.namelist())
            entropy = calculate_entropy(filepath)
        features = {
            "filename": [os.path.basename(filepath)],
            "size": [os.path.getsize(filepath)],
            "num_files": [file_count],
            "entropy": [entropy],
            "num_sections": [0],
            "num_pages": [0],
            "text_length": [0],
            "word_count": [0],
            "line_count": [0],
            "has_js": [0],
            "has_suspicious_strings": [0],
            "is_apk": [1]
        }
        return pd.DataFrame(features)
    except Exception:
        return empty_features(filename=os.path.basename(filepath))


# ---------------- TXT Feature Extraction ---------------- #
def extract_txt_features(filepath):
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            text = f.read()
        word_count = len(text.split())
        line_count = text.count("\n") + 1
        entropy = calculate_entropy(filepath)
        suspicious_strings = int(any(x in text.lower() for x in ["http://", "https://", "password", "key"]))
        features = {
            "filename": [os.path.basename(filepath)],
            "size": [os.path.getsize(filepath)],
            "word_count": [word_count],
            "line_count": [line_count],
            "entropy": [entropy],
            "num_pages": [0],
            "num_sections": [0],
            "num_files": [0],
            "text_length": [0],
            "has_js": [0],
            "has_suspicious_strings": [suspicious_strings],
            "is_txt": [1]
         }
        return pd.DataFrame(features)
    except Exception:
        return empty_features(filename=os.path.basename(filepath))


# ---------------- Unified File Feature Extractor ---------------- #
def extract_file_features(filepath, model_type="malware", filetype=None, feature_list=None):
    try:
        if filetype is None:
            filetype = os.path.splitext(filepath)[1].lower().lstrip(".")

        if filetype == "pdf":
            df = extract_pdf_features(filepath)
        elif filetype == "exe":
            df = extract_exe_features(filepath, feature_list)
        elif filetype == "apk":
            df = extract_apk_features(filepath)
        elif filetype == "csv":
            df = pd.read_csv(filepath)
            df["filename"] = os.path.basename(filepath)
            df["is_csv"] = 1
        elif filetype == "txt":
            df = extract_txt_features(filepath)
        else:
            df = empty_features(feature_list, filename=os.path.basename(filepath))

        # Align features to model expectations
        if feature_list:
            for f in feature_list:
                if f not in df.columns:
                    df[f] = 0
            df = df[feature_list]
            df = df.apply(pd.to_numeric, errors="coerce").fillna(0)

        return df
    except Exception:
        return empty_features(feature_list, filename=os.path.basename(filepath)) 