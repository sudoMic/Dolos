import email
import email.policy
from email import message_from_file
from pathlib import Path


def parse_eml(filepath: str) -> dict:
    """
    Parses a .eml file and returns a structured dictionary with headers, body and attachments.
    """
    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {filepath}")
    if path.suffix.lower() != ".eml":
        raise ValueError(f"File must be a .eml: {filepath}")

    with open(path, "r", encoding="utf-8", errors="replace") as f:
        msg = message_from_file(f, policy=email.policy.compat32)

    result = {
        "headers": _extract_headers(msg),
        "body": _extract_body(msg),
        "attachments": _extract_attachments(msg),
    }

    return result


def _extract_headers(msg) -> dict:
    """
    Extracts all relevant headers from the message.
    """
    headers = {}

    # Main fields
    headers["from"] = msg.get("From", "")
    headers["to"] = msg.get("To", "")
    headers["reply_to"] = msg.get("Reply-To", "")
    headers["return_path"] = msg.get("Return-Path", "")
    headers["subject"] = msg.get("Subject", "")
    headers["date"] = msg.get("Date", "")
    headers["message_id"] = msg.get("Message-ID", "")
    headers["x_mailer"] = msg.get("X-Mailer", "")

    # Authentication results (SPF, DKIM, DMARC)
    headers["authentication_results"] = msg.get("Authentication-Results", "")
    headers["received_spf"] = msg.get("Received-SPF", "")
    headers["dkim_signature"] = msg.get("DKIM-Signature", "")

    # Received chain — each hop is a list element
    headers["received"] = msg.get_all("Received", [])

    return headers


def _extract_body(msg) -> dict:
    """
    Extracts the message body as plain text and HTML. Also handles emails with body entirely in base64.
    """
    import base64
    import quopri

    body = {
        "text": "",
        "html": "",
    }

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            disposition = str(part.get("Content-Disposition", ""))

            if "attachment" in disposition:
                continue

            if content_type == "text/plain":
                payload = part.get_payload(decode=True)
                if payload:
                    body["text"] = payload.decode("utf-8", errors="replace")

            elif content_type == "text/html":
                payload = part.get_payload(decode=True)
                if payload:
                    body["html"] = payload.decode("utf-8", errors="replace")
    else:
        # Handle non-multipart email with explicit encoding
        cte = msg.get("Content-Transfer-Encoding", "").lower()
        payload = msg.get_payload()

        if cte == "base64" and isinstance(payload, str):
            try:
                decoded = base64.b64decode(payload.replace("\n", "").replace("\r", ""))
                content = decoded.decode("utf-8", errors="replace")
            except Exception:
                content = payload
        elif cte == "quoted-printable" and isinstance(payload, str):
            try:
                content = quopri.decodestring(payload.encode()).decode("utf-8", errors="replace")
            except Exception:
                content = payload
        else:
            cte = msg.get("Content-Transfer-Encoding", "").lower()
            if cte:
                raw = msg.get_payload(decode=True)
                content = raw.decode("utf-8", errors="replace") if raw else ""
            else:
                # No transfer encoding — payload is already a Unicode string
                content = msg.get_payload(decode=False) or ""

        # Determine if content is HTML or plain text
        content_type = msg.get_content_type()
        if content_type == "text/html":
            body["html"] = content
        else:
            body["text"] = content

    return body


def _extract_attachments(msg) -> list:
    """
    Extracts attachment metadata (not the content — that will be handled by the attachment_analyzer).
    """
    attachments = []

    if msg.is_multipart():
        for part in msg.walk():
            disposition = str(part.get("Content-Disposition", ""))
            if "attachment" in disposition:
                attachments.append({
                    "filename": part.get_filename("unknown"),
                    "content_type": part.get_content_type(),
                    "payload": part.get_payload(decode=True),  # raw bytes
                })

    return attachments
