import hashlib
import magic
import re
from pathlib import Path


# Extensions considered high risk
HIGH_RISK_EXTENSIONS = {
    ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js",
    ".jar", ".scr", ".pif", ".com", ".msi", ".hta",
}

# Expected MIME types per extension — to detect mismatches
MIME_EXTENSION_MAP = {
    ".pdf":  ["application/pdf"],
    ".doc":  ["application/msword"],
    ".docx": ["application/vnd.openxmlformats-officedocument.wordprocessingml.document"],
    ".xls":  ["application/vnd.ms-excel"],
    ".xlsx": ["application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"],
    ".zip":  ["application/zip", "application/x-zip-compressed"],
    ".png":  ["image/png"],
    ".jpg":  ["image/jpeg"],
    ".jpeg": ["image/jpeg"],
    ".gif":  ["image/gif"],
}


def analyze_attachments(attachments: list) -> dict:
    """
    Analyze attachments extracted by the parser.
    Returns hashes, real MIME type, and anomalies.
    """
    results = []

    for attachment in attachments:
        filename = attachment.get("filename", "unknown")
        payload = attachment.get("payload")

        if not payload:
            continue

        result = {
            "filename": filename,
            "size_bytes": len(payload),
            "hashes": _compute_hashes(payload),
            "declared_extension": _get_extension(filename),
            "real_mime": _get_real_mime(payload),
            "double_extension": _check_double_extension(filename),
            "high_risk_extension": _check_high_risk_extension(filename),
            "office_macros": None,
            "pdf_analysis": None,
            "anomalies": [],
        }

        # Macro analysis for Office files
        if result["declared_extension"] in (".doc", ".xls", ".ppt", ".docm", ".xlsm"):
            result["office_macros"] = _check_office_macros(payload, filename)
        
        # PDF analysis
        if result["declared_extension"] == ".pdf":
            result["pdf_analysis"] = _check_pdf(payload, filename)
        
        result["anomalies"] = _collect_anomalies(result)
        results.append(result)

    return {
        "count": len(results),
        "attachments": results,
    }


def _compute_hashes(payload: bytes) -> dict:
    return {
        "md5":    hashlib.md5(payload).hexdigest(),
        "sha256": hashlib.sha256(payload).hexdigest(),
    }


def _get_extension(filename: str) -> str:
    """
    Return the final file extension.
    E.g.: 'invoice.pdf.exe' → '.exe'
    """
    return Path(filename).suffix.lower()


def _get_real_mime(payload: bytes) -> str:
    """
    Use magic bytes to determine the real file type.
    """
    try:
        mime = magic.from_buffer(payload, mime=True)
        return mime
    except Exception:
        return "unknown"


def _check_double_extension(filename: str) -> bool:
    """
    Detect double extensions like 'invoice.pdf.exe'.
    Counts dots in the filename (excluding leading dot).
    """
    name = Path(filename).name
    parts = name.split(".")
    # If at least 3 parts: name, ext1, ext2
    if len(parts) >= 3:
        # Check that the second-to-last extension is known (e.g. .pdf, .doc)
        penultimate_ext = f".{parts[-2].lower()}"
        if penultimate_ext in MIME_EXTENSION_MAP:
            return True
    return False


def _check_high_risk_extension(filename: str) -> bool:
    ext = _get_extension(filename)
    return ext in HIGH_RISK_EXTENSIONS


def _check_office_macros(payload: bytes, filename: str) -> dict:
    """
    Use oletools to detect VBA macros in legacy Office files.
    """
    try:
        import tempfile
        import os
        from oletools.olevba import VBA_Parser

        # Write payload to a temporary file
        with tempfile.NamedTemporaryFile(delete=False, suffix=_get_extension(filename)) as tmp:
            tmp.write(payload)
            tmp_path = tmp.name

        try:
            vba_parser = VBA_Parser(tmp_path)
            if vba_parser.detect_vba_macros():
                macros = []
                for (_, _, vba_filename, vba_code) in vba_parser.extract_macros():
                    macros.append({
                        "module": vba_filename,
                        "code_preview": vba_code[:200] if vba_code else "",
                    })
                return {
                    "has_macros": True,
                    "macro_count": len(macros),
                    "macros": macros,
                }
            else:
                return {"has_macros": False}
        finally:
            os.unlink(tmp_path)

    except Exception as e:
        return {"has_macros": None, "error": str(e)}


def _collect_anomalies(result: dict) -> list:
    anomalies = []

    # Double extension
    if result["double_extension"]:
        anomalies.append({
            "type": "DOUBLE_EXTENSION",
            "description": f"Double extension detected: {result['filename']}",
            "severity": "high",
            "score": 30,
        })

    # High risk extension
    if result["high_risk_extension"]:
        anomalies.append({
            "type": "HIGH_RISK_EXTENSION",
            "description": f"High risk extension: {result['declared_extension']}",
            "severity": "critical",
            "score": 40,
        })

    # MIME mismatch — real type differs from declared extension
    declared_ext = result["declared_extension"]
    real_mime = result["real_mime"]
    if declared_ext in MIME_EXTENSION_MAP:
        expected_mimes = MIME_EXTENSION_MAP[declared_ext]
        if real_mime not in expected_mimes:
            anomalies.append({
                "type": "MIME_MISMATCH",
                "description": f"Real type '{real_mime}' does not match declared extension '{declared_ext}'",
                "severity": "high",
                "score": 35,
            })

    # Office Macros
    macros = result.get("office_macros")
    if macros and macros.get("has_macros"):
        anomalies.append({
            "type": "OFFICE_MACROS",
            "description": f"VBA Macros detected: {macros.get('macro_count', 0)} moduli",
            "severity": "high",
            "score": 30,
        })
        
    # Suspicious PDF
    pdf = result.get("pdf_analysis")
    if pdf and pdf.get("has_javascript"):
        anomalies.append({
            "type": "PDF_JAVASCRIPT",
            "description": f"PDF '{result['filename']}' contains JavaScript or automatic action",
            "severity": "critical",
            "score": 50,
        })
    if pdf and pdf.get("embedded_urls"):
        anomalies.append({
            "type": "PDF_EMBEDDED_URLS",
            "description": f"PDF '{result['filename']}' contains {len(pdf['embedded_urls'])} URL: {', '.join(pdf['embedded_urls'][:3])}",
            "severity": "high",
            "score": 20,
        })        

    return anomalies
    
        
def _check_pdf(payload: bytes, filename: str) -> dict:
    import io
    try:
        from pdfminer.high_level import extract_text
        from pdfminer.pdfdocument import PDFDocument
        from pdfminer.pdfparser import PDFParser
        from pdfminer.pdftypes import resolve1, PDFObjRef
    except ImportError:
        return {"error": "pdfminer.six not installed"}

    result = {
        "has_javascript": False,
        "embedded_urls": [],
        "suspicious": False,
    }

    try:
        parser = PDFParser(io.BytesIO(payload))
        doc = PDFDocument(parser)
        catalog = resolve1(doc.catalog)

        if "AA" in catalog or "OpenAction" in catalog:
            result["has_javascript"] = True
            result["suspicious"] = True

        # Scan all PDF objects looking for JS strings
        js_content = ""
        for xref in doc.xrefs:
            for objid in xref.get_objids():
                try:
                    obj = resolve1(doc.getobj(objid))
                    if isinstance(obj, dict):
                        for key in ("JS", "JavaScript"):
                            if key in obj:
                                js_val = resolve1(obj[key])
                                if isinstance(js_val, bytes):
                                    js_content += js_val.decode(errors="ignore")
                                elif isinstance(js_val, str):
                                    js_content += js_val
                except Exception:
                    continue

        # Extract URLs from JS content
        if js_content:
            urls = re.findall(r"https?://[\w./\-?=&%+#]+", js_content)
            result["embedded_urls"] = list(set(urls))

        # Extract URLs from visible text as well
        text = extract_text(io.BytesIO(payload))
        text_urls = re.findall(r"https?://[\w./\-?=&%+#]+", text)
        result["embedded_urls"] = list(set(result["embedded_urls"] + text_urls))

    except Exception as e:
        result["error"] = str(e)

    return result
