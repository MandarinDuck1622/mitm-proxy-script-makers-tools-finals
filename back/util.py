# util.py
"""
Shared utilities for Proxy1 / Proxy2 MITM addons.

This module provides:
- Logging helpers (with optional file logging)
- HTTP body helpers (gzip handling, content-length fix)
- Crypto helpers (encrypt/decrypt with different algorithms)
- Secret / regex extraction utilities
- Simple rate limiter
"""

from __future__ import annotations

import gzip
import logging
import re
from io import BytesIO
from typing import Tuple, Optional, Dict, Any, List

from base64 import b64encode, b64decode
from time import time

from Crypto.Cipher import AES, ChaCha20, DES3, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA


# ---------------------------------------------------------------------------
# 1. Logging helpers  (can support "Log Traffic to File")
# ---------------------------------------------------------------------------

logger = logging.getLogger("mitm_proxy_tool")

if not logger.handlers:
    logger.setLevel(logging.INFO)
    stream_handler = logging.StreamHandler()
    formatter = logging.Formatter(
        "[%(asctime)s] %(levelname)s - %(name)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)


def configure_file_logging(log_path: str) -> None:
    """
    Enable logging to a file in addition to the console.

    Use from script1/script2 if the user enabled "Log Traffic to File".
    """
    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    formatter = logging.Formatter(
        "[%(asctime)s] %(levelname)s - %(name)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    logger.info(f"File logging enabled: {log_path}")


# ---------------------------------------------------------------------------
# 2. HTTP body helpers (used by script1/script2)
# ---------------------------------------------------------------------------

def _decode_body(headers: Dict[str, str], raw: bytes) -> Tuple[bytes, Optional[str]]:
    """
    Internal: decode body based on Content-Encoding.
    Currently supports gzip; returns (decoded_bytes, encoding_used).
    """
    encoding = headers.get("Content-Encoding", "").lower()
    if encoding == "gzip":
        try:
            with gzip.GzipFile(fileobj=BytesIO(raw)) as f:
                data = f.read()
            return data, "gzip"
        except Exception as exc:
            logger.warning(f"Failed to gunzip body: {exc}")
            return raw, None
    return raw, None


def _encode_body(headers: Dict[str, str], body: bytes, encoding: Optional[str]) -> bytes:
    """
    Internal: re-encode body if it was gzip before.
    Also fixes Content-Length.
    """
    if encoding == "gzip":
        out = BytesIO()
        with gzip.GzipFile(fileobj=out, mode="wb") as f:
            f.write(body)
        encoded = out.getvalue()
        headers["Content-Encoding"] = "gzip"
    else:
        encoded = body
        headers.pop("Content-Encoding", None)

    headers["Content-Length"] = str(len(encoded))
    return encoded


def get_request_body(flow) -> Tuple[bytes, Optional[str]]:
    """
    Return (plaintext_body, encoding_used) for a request.
    Handles gzip if present.
    """
    raw = flow.request.raw_content or b""
    headers = dict(flow.request.headers)
    body, enc = _decode_body(headers, raw)
    return body, enc


def set_request_body(flow, body: bytes, enc: Optional[str]) -> None:
    """
    Replace request body with new bytes and fix headers.
    """
    headers = dict(flow.request.headers)
    encoded = _encode_body(headers, body, enc)
    flow.request.headers.clear()
    for k, v in headers.items():
        flow.request.headers[k] = v
    flow.request.raw_content = encoded


def get_response_body(flow) -> Tuple[bytes, Optional[str]]:
    """
    Return (plaintext_body, encoding_used) for a response.
    Handles gzip if present.
    """
    raw = flow.response.raw_content or b""
    headers = dict(flow.response.headers)
    body, enc = _decode_body(headers, raw)
    return body, enc


def set_response_body(flow, body: bytes, enc: Optional[str]) -> None:
    """
    Replace response body with new bytes and fix headers.
    """
    headers = dict(flow.response.headers)
    encoded = _encode_body(headers, body, enc)
    flow.response.headers.clear()
    for k, v in headers.items():
        flow.response.headers[k] = v
    flow.response.raw_content = encoded


# ---------------------------------------------------------------------------
# 3. Pretty summaries & regex/secret helpers
# ---------------------------------------------------------------------------

def pretty_flow_summary(method: str, url: str,
                        headers: Dict[str, str],
                        body: bytes,
                        max_body_len: int = 512) -> str:
    """
    Render a short, human-readable summary of an HTTP flow for logging.
    """
    body_preview = body[:max_body_len].decode("utf-8", errors="replace")
    lines = [
        f"{method} {url}",
        "Headers:",
    ]
    for k, v in headers.items():
        lines.append(f"  {k}: {v}")
    lines.append("Body (preview):")
    lines.append(body_preview)
    return "\n".join(lines)


# Basic secret patterns (generic; can be tuned later)
_SECRET_PATTERNS = [
    r"(?i)apikey\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{16,}['\"]?",
    r"(?i)authorization\s*[:=]\s*['\"][^'\"]+['\"]",
    r"(?i)password\s*[:=]\s*['\"][^'\"]+['\"]",
    r"(?i)bearer\s+[A-Za-z0-9\-._~+/]+=*",
]


def scan_secrets(text: str) -> List[str]:
    """
    Simple secret detection on a plaintext string.
    Used by script1/script2 when logging decrypted content.
    """
    findings: List[str] = []
    for pattern in _SECRET_PATTERNS:
        for match in re.findall(pattern, text):
            findings.append(match)
    return findings


def extract_with_regex(pattern: str, text: str) -> List[str]:
    """
    Generic regex extraction utility.
    Can be used for "Extract & Save Data (Regex)" feature.
    """
    try:
        return re.findall(pattern, text)
    except re.error as exc:
        logger.warning(f"Invalid regex {pattern!r}: {exc}")
        return []


def extract_and_save(pattern: str, text: str, filepath: str) -> int:
    """
    Extract matches from text using a regex and append them to a file.
    Returns number of matches written.
    """
    matches = extract_with_regex(pattern, text)
    if not matches:
        return 0

    try:
        with open(filepath, "a", encoding="utf-8") as f:
            for m in matches:
                f.write(str(m) + "\n")
        logger.info(f"Saved {len(matches)} matches to {filepath}")
    except Exception as exc:
        logger.warning(f"Failed to write extracted data to {filepath}: {exc}")
        return 0

    return len(matches)


# ---------------------------------------------------------------------------
# 4. Crypto helpers (encrypt/decrypt)
# ---------------------------------------------------------------------------

def _normalize_key(key: str, length: int) -> bytes:
    """
    Ensure key is exactly `length` bytes (simple trunc/pad for demo purposes).
    For real-world crypto you should manage keys more carefully.

    New:
    - If key starts with "hex:", the rest is interpreted as hex bytes.
      Example:
        KEY = "hex:00112233445566778899AABBCCDDEEFF"
    - Otherwise, treat it as UTF-8 text like before.
    """
    if key.startswith("hex:"):
        hex_part = key[4:]
        try:
            b = bytes.fromhex(hex_part)
        except ValueError:
            # fallback: treat as plain text if hex invalid
            b = hex_part.encode("utf-8")
    else:
        b = key.encode("utf-8")

    if len(b) > length:
        return b[:length]
    if len(b) < length:
        return b.ljust(length, b"\0")
    return b


# AES-CBC

def aes_cbc_encrypt(plaintext: bytes, key: str) -> bytes:
    # 16 bytes = AES-128, sama seperti KEY di app.py website
    key_bytes = _normalize_key(key, 16)
    iv = get_random_bytes(16)
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv=iv)
    ct = cipher.encrypt(pad(plaintext, AES.block_size))
    return iv + ct


def aes_cbc_decrypt(ciphertext: bytes, key: str) -> bytes:
    key_bytes = _normalize_key(key, 16)
    iv, ct = ciphertext[:16], ciphertext[16:]
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv=iv)
    return unpad(cipher.decrypt(ct), AES.block_size)



# AES-256-GCM

def aes_gcm_encrypt(plaintext: bytes, key: str) -> bytes:
    key_bytes = _normalize_key(key, 32)
    cipher = AES.new(key_bytes, AES.MODE_GCM)
    ct, tag = cipher.encrypt_and_digest(plaintext)
    return cipher.nonce + tag + ct  # nonce | tag | ct


def aes_gcm_decrypt(ciphertext: bytes, key: str) -> bytes:
    key_bytes = _normalize_key(key, 32)
    nonce, tag, ct = ciphertext[:16], ciphertext[16:32], ciphertext[32:]
    cipher = AES.new(key_bytes, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ct, tag)


# ChaCha20

def chacha20_encrypt(plaintext: bytes, key: str) -> bytes:
    key_bytes = _normalize_key(key, 32)
    nonce = get_random_bytes(8)
    cipher = ChaCha20.new(key=key_bytes, nonce=nonce)
    ct = cipher.encrypt(plaintext)
    return nonce + ct


def chacha20_decrypt(ciphertext: bytes, key: str) -> bytes:
    key_bytes = _normalize_key(key, 32)
    nonce, ct = ciphertext[:8], ciphertext[8:]
    cipher = ChaCha20.new(key=key_bytes, nonce=nonce)
    return cipher.decrypt(ct)


# 3DES-CBC

def des3_cbc_encrypt(plaintext: bytes, key: str) -> bytes:
    key_bytes = _normalize_key(key, 24)
    iv = get_random_bytes(8)
    cipher = DES3.new(key_bytes, DES3.MODE_CBC, iv=iv)
    ct = cipher.encrypt(pad(plaintext, DES3.block_size))
    return iv + ct


def des3_cbc_decrypt(ciphertext: bytes, key: str) -> bytes:
    key_bytes = _normalize_key(key, 24)
    iv, ct = ciphertext[:8], ciphertext[8:]
    cipher = DES3.new(key_bytes, DES3.MODE_CBC, iv=iv)
    return unpad(cipher.decrypt(ct), DES3.block_size)


# RSA (demo use)

def rsa_encrypt(plaintext: bytes, public_key_pem: str) -> bytes:
    pub = RSA.import_key(public_key_pem.encode("utf-8"))
    cipher = PKCS1_OAEP.new(pub)
    return cipher.encrypt(plaintext)


def rsa_decrypt(ciphertext: bytes, private_key_pem: str) -> bytes:
    priv = RSA.import_key(private_key_pem.encode("utf-8"))
    cipher = PKCS1_OAEP.new(priv)
    return cipher.decrypt(ciphertext)


def encrypt(data: bytes, algorithm: str, key: str, **kwargs) -> bytes:
    """
    Generic encrypt wrapper used by script1/script2.
    `algorithm` is a string like "aes-256-gcm", "aes-cbc", "chacha20", "3des", "rsa".
    """
    algo = algorithm.lower()

    if "gcm" in algo:
        return aes_gcm_encrypt(data, key)
    if "cbc" in algo and "aes" in algo:
        return aes_cbc_encrypt(data, key)
    if "chacha" in algo:
        return chacha20_encrypt(data, key)
    if "3des" in algo or "des3" in algo:
        return des3_cbc_encrypt(data, key)
    if "rsa" in algo:
        public_key = kwargs.get("public_key", key)
        return rsa_encrypt(data, public_key)

    logger.warning(f"Unknown algorithm {algorithm!r}, returning data unchanged.")
    return data


def decrypt(data: bytes, algorithm: str, key: str, **kwargs) -> bytes:
    """
    Generic decrypt wrapper used by script1/script2.
    """
    algo = algorithm.lower()

    if "gcm" in algo:
        return aes_gcm_decrypt(data, key)
    if "cbc" in algo and "aes" in algo:
        return aes_cbc_decrypt(data, key)
    if "chacha" in algo:
        return chacha20_decrypt(data, key)
    if "3des" in algo or "des3" in algo:
        return des3_cbc_decrypt(data, key)
    if "rsa" in algo:
        private_key = kwargs.get("private_key", key)
        return rsa_decrypt(data, private_key)

    logger.warning(f"Unknown algorithm {algorithm!r}, returning data unchanged.")
    return data


# ---------------------------------------------------------------------------
# 5. Simple rate limiter
# ---------------------------------------------------------------------------

class SimpleRateLimiter:
    """
    Simple QPS-based rate limiter.

    Example:
        limiter = SimpleRateLimiter(2.0)  # 2 operations per second
        if limiter.allow():
            do_something()
    """

    def __init__(self, qps: float):
        self.qps = qps
        self.period = 1.0 / qps if qps > 0 else 0
        self._last = 0.0

    def allow(self) -> bool:
        now = time()
        if self._last + self.period <= now:
            self._last = now
            return True
        return False
