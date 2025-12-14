# script2.py  (TEMPLATE)

import json
import base64

from typing import Optional, List

import asyncio
import re
from mitmproxy import http, options
from mitmproxy.tools.dump import DumpMaster

from util import (
    logger,
    encrypt,
    decrypt,
    get_request_body,
    set_request_body,
    get_response_body,
    set_response_body,
    pretty_flow_summary,
    scan_secrets,
    configure_file_logging,
    extract_and_save,
    SimpleRateLimiter,
)

# Placeholders replaced by app.py:
TARGET_DOMAIN = "__TARGET_DOMAIN__"
ALGORITHM = "__ALGORITHM__"
KEY = __KEY__

ENCRYPT_TO_SERVER = "__ENCRYPT_TO_SERVER__"
DECRYPT_FROM_SERVER = "__DECRYPT_FROM_SERVER__"
ALLOWED_METHODS = "__ALLOWED_METHODS__"

CREDENTIAL_FORMAT = "__CREDENTIAL_FORMAT__"

LOG_TO_FILE = "__LOG_TO_FILE__"
LOG_FILE_PATH = "__LOG_FILE_PATH__"

REGEX_EXTRACT_PATTERN = "__REGEX_EXTRACT_PATTERN__"
REGEX_EXTRACT_FILE = "__REGEX_EXTRACT_FILE__"
RATE_LIMIT_QPS = "__RATE_LIMIT_QPS__"

FILTER_BY_DOMAIN = "__FILTER_BY_DOMAIN__"
FILTER_DOMAIN_PATTERN = "__FILTER_DOMAIN_PATTERN__"
FILTER_BY_URL_PATH = "__FILTER_BY_URL_PATH__"
FILTER_URL_PATH_PATTERN = "__FILTER_URL_PATH_PATTERN__"
FILTER_BY_HTTP_METHOD = "__FILTER_BY_HTTP_METHOD__"
FILTER_BY_REQUEST_HEADER = "__FILTER_BY_REQUEST_HEADER__"
FILTER_REQUEST_HEADER_NAME = "__FILTER_REQUEST_HEADER_NAME__"
FILTER_REQUEST_HEADER_VALUE = "__FILTER_REQUEST_HEADER_VALUE__"
FILTER_BY_RESPONSE_HEADER = "__FILTER_BY_RESPONSE_HEADER__"
FILTER_RESPONSE_HEADER_NAME = "__FILTER_RESPONSE_HEADER_NAME__"
FILTER_RESPONSE_HEADER_VALUE = "__FILTER_RESPONSE_HEADER_VALUE__"
FILTER_BY_BODY_CONTENT = "__FILTER_BY_BODY_CONTENT__"
FILTER_BODY_CONTENT_PATTERN = "__FILTER_BODY_CONTENT_PATTERN__"
FILTER_BY_CLIENT_IP = "__FILTER_BY_CLIENT_IP__"
FILTER_CLIENT_IP_ADDRESS = "__FILTER_CLIENT_IP_ADDRESS__"

MODIFY_USER_AGENT_ENABLED = "__MODIFY_USER_AGENT_ENABLED__"
CUSTOM_USER_AGENT = "__CUSTOM_USER_AGENT__"
MODIFY_HOST_HEADER_ENABLED = "__MODIFY_HOST_HEADER_ENABLED__"
CUSTOM_HOST_HEADER = "__CUSTOM_HOST_HEADER__"
CHANGE_REQUEST_METHOD_ENABLED = "__CHANGE_REQUEST_METHOD_ENABLED__"
REQUEST_METHOD_FROM = "__REQUEST_METHOD_FROM__"
REQUEST_METHOD_TO = "__REQUEST_METHOD_TO__"
REDIRECT_REQUEST_ENABLED = "__REDIRECT_REQUEST_ENABLED__"
REDIRECT_TO_HOST = "__REDIRECT_TO_HOST__"
REDIRECT_TO_PORT = "__REDIRECT_TO_PORT__"
REWRITE_URL_ENABLED = "__REWRITE_URL_ENABLED__"
URL_REWRITE_PATTERN = "__URL_REWRITE_PATTERN__"
URL_REWRITE_WITH = "__URL_REWRITE_WITH__"

BLOCK_ENABLED = "__BLOCK_ENABLED__"
BLOCK_PATTERN = "__BLOCK_PATTERN__"

ADD_REQ_HEADERS_ENABLED = "__ADD_REQ_HEADERS_ENABLED__"
REQ_HEADERS_TO_ADD = "__REQ_HEADERS_TO_ADD__"
REMOVE_REQ_HEADERS_ENABLED = "__REMOVE_REQ_HEADERS_ENABLED__"
REQ_HEADERS_TO_REMOVE = "__REQ_HEADERS_TO_REMOVE__"

REPLACE_REQUEST_BODY_ENABLED = "__REPLACE_REQUEST_BODY_ENABLED__"
REQ_BODY_REPLACE_PATTERN = "__REQ_BODY_REPLACE_PATTERN__"
REQ_BODY_REPLACE_WITH = "__REQ_BODY_REPLACE_WITH__"

ADD_RESP_HEADERS_ENABLED = "__ADD_RESP_HEADERS_ENABLED__"
RESP_HEADERS_TO_ADD = "__RESP_HEADERS_TO_ADD__"
REMOVE_RESP_HEADERS_ENABLED = "__REMOVE_RESP_HEADERS_ENABLED__"
RESP_HEADERS_TO_REMOVE = "__RESP_HEADERS_TO_REMOVE__"

REPLACE_RESPONSE_BODY_ENABLED = "__REPLACE_RESPONSE_BODY_ENABLED__"
RESP_BODY_REPLACE_PATTERN = "__RESP_BODY_REPLACE_PATTERN__"
RESP_BODY_REPLACE_WITH = "__RESP_BODY_REPLACE_WITH__"

INJECT_HTML_JS_ENABLED = "__INJECT_HTML_JS_ENABLED__"
HTML_JS_INJECTION_CODE = "__HTML_JS_INJECTION_CODE__"

MODIFY_COOKIES_ENABLED = "__MODIFY_COOKIES_ENABLED__"
COOKIE_MODIFICATIONS = "__COOKIE_MODIFICATIONS__"

CHANGE_STATUS_CODE_ENABLED = "__CHANGE_STATUS_CODE_ENABLED__"
STATUS_CODE_FROM = "__STATUS_CODE_FROM__"
STATUS_CODE_TO = "__STATUS_CODE_TO__"

# Advanced & Utility placeholders
AUTO_HANDLE_AUTH_ENABLED = "__AUTO_HANDLE_AUTH_ENABLED__"
AUTH_TOKEN = "__AUTH_TOKEN__"
REPLAY_ATTACK_ENABLED = "__REPLAY_ATTACK_ENABLED__"
REPLAY_COUNT = "__REPLAY_COUNT__"
ENABLE_AUTO_SCAN = "__ENABLE_AUTO_SCAN__"
CUSTOM_HEADERS_GLOBAL = "__CUSTOM_HEADERS_GLOBAL__"
CUSTOM_DECRYPT_FUNCTION_ENABLED = "__CUSTOM_DECRYPT_FUNCTION_ENABLED__"
DECRYPT_FUNCTION_CODE = "__DECRYPT_FUNCTION_CODE__"
CUSTOM_ENCRYPT_FUNCTION_ENABLED = "__CUSTOM_ENCRYPT_FUNCTION_ENABLED__"
ENCRYPT_FUNCTION_CODE = "__ENCRYPT_FUNCTION_CODE__"


def _split_nonempty_lines(value: str) -> List[str]:
    return [line.strip() for line in (value or "").splitlines() if line.strip()]


def _parse_header_lines(value: str) -> List[tuple[str, str]]:
    """
    Parse multi-line "Header: value" into list of (name, value).
    """
    result: list[tuple[str, str]] = []
    for line in _split_nonempty_lines(value):
        if ":" in line:
            name, val = line.split(":", 1)
            result.append((name.strip(), val.strip()))
    return result


def _parse_header_names(value: str) -> List[str]:
    return _split_nonempty_lines(value)


class Proxy2:
    """
    Server-side encryption/decryption proxy.
    """
    LOGIN_PATHS = ["/login", "/login.html", "/register", "/register.html"]

    def _is_credential_request(self, flow: http.HTTPFlow) -> bool:
        """
        Only process login/register POSTs to the target domain.
        """
        if flow.request.host != self.target_domain:
            return False
        if flow.request.method.upper() != "POST":
            return False
        path = flow.request.path.split("?", 1)[0]
        return path in self.LOGIN_PATHS

    def _encrypt_field_b64_block(self, value: str) -> str:
        if value is None:
            return ""
        try:
            plaintext = value.encode("utf-8")
            ciphertext = encrypt(plaintext, algorithm=self.algorithm, key=self.key)
            return base64.b64encode(ciphertext).decode("ascii")
        except Exception as exc:
            logger.warning(f"Proxy2: failed to encrypt field (b64_block): {exc}")
            return value


    def _encrypt_field_hex_with_iv(self, value: str) -> tuple[str, str]:
        """
        Encrypt plaintext → (cipher_hex, iv_hex) for hex_iv_split mode.
        """
        if value is None:
            return "", ""
        try:
            plaintext = value.encode("utf-8")
            combined = encrypt(plaintext, algorithm=self.algorithm, key=self.key)
            iv = combined[:16]
            ct = combined[16:]
            return ct.hex(), iv.hex()
        except Exception as exc:
            logger.warning(f"Proxy2: failed to encrypt field (hex+iv): {exc}")
            return value, ""



    def __init__(
        self,
        master: Optional[DumpMaster] = None,
        target_domain: str = TARGET_DOMAIN,
        algorithm: str = ALGORITHM,
        key: str = KEY,
        encrypt_to_server: Optional[bool] = ENCRYPT_TO_SERVER,
        decrypt_from_server: Optional[bool] = DECRYPT_FROM_SERVER,
        allowed_methods: Optional[List[str]] = None,
        log_to_file: Optional[bool] = LOG_TO_FILE,
        log_file_path: str = LOG_FILE_PATH,
        regex_pattern: str = REGEX_EXTRACT_PATTERN,
        regex_file: str = REGEX_EXTRACT_FILE,
        rate_limit_qps: float = RATE_LIMIT_QPS,
    ):
        # Convert simple placeholders that might still be strings:
        if isinstance(encrypt_to_server, str):
            encrypt_to_server = encrypt_to_server == "True"
        if isinstance(decrypt_from_server, str):
            decrypt_from_server = decrypt_from_server == "True"
        if isinstance(log_to_file, str):
            log_to_file = log_to_file == "True"

        # Allowed methods list may come from placeholder
        if allowed_methods is None:
            if isinstance(ALLOWED_METHODS, list):
                allowed_methods = ALLOWED_METHODS
            elif isinstance(ALLOWED_METHODS, str) and ALLOWED_METHODS.strip():
                # ALLOWED_METHODS is something like "['GET','POST']"
                try:
                    txt = ALLOWED_METHODS.strip()
                    txt = txt.strip("[]")
                    parts = [p.strip().strip("'\"") for p in txt.split(",") if p.strip()]
                    allowed_methods = [p.upper() for p in parts]
                except Exception:
                    allowed_methods = []
            else:
                allowed_methods = []

        # Rate limit placeholder may come as string
        if isinstance(rate_limit_qps, str):
            try:
                rate_limit_qps = float(rate_limit_qps)
            except ValueError:
                rate_limit_qps = 0.0

        self.master = master
        self.target_domain = target_domain
        self.algorithm = algorithm
        self.key = key
        self.encrypt_to_server = bool(encrypt_to_server)
        self.decrypt_from_server = bool(decrypt_from_server)
        self.allowed_methods = allowed_methods
        self.log_to_file = bool(log_to_file)
        self.log_file_path = log_file_path or "./proxy2_logs.txt"

        self.regex_pattern = (regex_pattern or "").strip()
        self.regex_file = (regex_file or "").strip()

        self.rate_limit_qps = float(rate_limit_qps) if rate_limit_qps else 0.0
        self.rate_limiter = SimpleRateLimiter(self.rate_limit_qps) if self.rate_limit_qps > 0 else None

                # -------------------------
        # Targeting & Filtering config
        # -------------------------
        # Booleans (placeholder -> bool)
        self.filter_by_domain = (FILTER_BY_DOMAIN == "True") if isinstance(FILTER_BY_DOMAIN, str) else bool(FILTER_BY_DOMAIN)
        self.filter_domain_pattern = (FILTER_DOMAIN_PATTERN or "").strip()

        self.filter_by_url_path = (FILTER_BY_URL_PATH == "True") if isinstance(FILTER_BY_URL_PATH, str) else bool(FILTER_BY_URL_PATH)
        self.filter_url_path_pattern = (FILTER_URL_PATH_PATTERN or "").strip()

        self.filter_by_http_method = (FILTER_BY_HTTP_METHOD == "True") if isinstance(FILTER_BY_HTTP_METHOD, str) else bool(FILTER_BY_HTTP_METHOD)

        self.filter_by_request_header = (FILTER_BY_REQUEST_HEADER == "True") if isinstance(FILTER_BY_REQUEST_HEADER, str) else bool(FILTER_BY_REQUEST_HEADER)
        self.filter_request_header_name = (FILTER_REQUEST_HEADER_NAME or "").strip()
        self.filter_request_header_value = (FILTER_REQUEST_HEADER_VALUE or "").strip()

        self.filter_by_response_header = (FILTER_BY_RESPONSE_HEADER == "True") if isinstance(FILTER_BY_RESPONSE_HEADER, str) else bool(FILTER_BY_RESPONSE_HEADER)
        self.filter_response_header_name = (FILTER_RESPONSE_HEADER_NAME or "").strip()
        self.filter_response_header_value = (FILTER_RESPONSE_HEADER_VALUE or "").strip()

        self.filter_by_body_content = (FILTER_BY_BODY_CONTENT == "True") if isinstance(FILTER_BY_BODY_CONTENT, str) else bool(FILTER_BY_BODY_CONTENT)
        self.filter_body_content_pattern = (FILTER_BODY_CONTENT_PATTERN or "").strip()

        self.filter_by_client_ip = (FILTER_BY_CLIENT_IP == "True") if isinstance(FILTER_BY_CLIENT_IP, str) else bool(FILTER_BY_CLIENT_IP)
        self.filter_client_ip_address = (FILTER_CLIENT_IP_ADDRESS or "").strip()

        # Compile patterns as regex where it makes sense
        self.filter_domain_regex = re.compile(self.filter_domain_pattern, re.IGNORECASE) if self.filter_domain_pattern else None
        self.filter_url_path_regex = re.compile(self.filter_url_path_pattern, re.IGNORECASE) if self.filter_url_path_pattern else None
        self.filter_body_regex = re.compile(self.filter_body_content_pattern, re.IGNORECASE) if self.filter_body_content_pattern else None
        self.filter_request_header_value_regex = (
            re.compile(self.filter_request_header_value, re.IGNORECASE)
            if self.filter_request_header_value
            else None
        )
        self.filter_response_header_value_regex = (
            re.compile(self.filter_response_header_value, re.IGNORECASE)
            if self.filter_response_header_value
            else None
        )
        self.filter_client_ip_regex = (
            re.compile(self.filter_client_ip_address, re.IGNORECASE)
            if self.filter_client_ip_address
            else None
        )


        # Compile regexes if present
        self.regex_compiled = re.compile(self.regex_pattern) if self.regex_pattern else None

        # Block / drop
        self.block_enabled = (BLOCK_ENABLED == "True") if isinstance(BLOCK_ENABLED, str) else bool(BLOCK_ENABLED)
        self.block_pattern = (BLOCK_PATTERN or "").strip()
        self.block_regex = re.compile(self.block_pattern) if self.block_pattern else None

        # Request header/body mods
        self.add_req_headers_enabled = (
            ADD_REQ_HEADERS_ENABLED == "True"
            if isinstance(ADD_REQ_HEADERS_ENABLED, str)
            else bool(ADD_REQ_HEADERS_ENABLED)
        )
        self.req_headers_to_add = _parse_header_lines(str(REQ_HEADERS_TO_ADD))

        self.remove_req_headers_enabled = (
            REMOVE_REQ_HEADERS_ENABLED == "True"
            if isinstance(REMOVE_REQ_HEADERS_ENABLED, str)
            else bool(REMOVE_REQ_HEADERS_ENABLED)
        )
        self.req_headers_to_remove = _parse_header_names(str(REQ_HEADERS_TO_REMOVE))

        self.replace_request_body_enabled = (
            REPLACE_REQUEST_BODY_ENABLED == "True"
            if isinstance(REPLACE_REQUEST_BODY_ENABLED, str)
            else bool(REPLACE_REQUEST_BODY_ENABLED)
        )
        self.req_body_replace_pattern = (REQ_BODY_REPLACE_PATTERN or "").strip()
        self.req_body_replace_with = (REQ_BODY_REPLACE_WITH or "").replace("\\n", "\n")

        self.req_body_regex = (
            re.compile(self.req_body_replace_pattern) if self.req_body_replace_pattern else None
        )

                # Advanced request mods: UA / Host / method / redirect / rewrite URL
        self.modify_user_agent_enabled = (
            MODIFY_USER_AGENT_ENABLED == "True"
            if isinstance(MODIFY_USER_AGENT_ENABLED, str)
            else bool(MODIFY_USER_AGENT_ENABLED)
        )
        self.custom_user_agent = (CUSTOM_USER_AGENT or "").strip()

        self.modify_host_header_enabled = (
            MODIFY_HOST_HEADER_ENABLED == "True"
            if isinstance(MODIFY_HOST_HEADER_ENABLED, str)
            else bool(MODIFY_HOST_HEADER_ENABLED)
        )
        self.custom_host_header = (CUSTOM_HOST_HEADER or "").strip()

        self.change_request_method_enabled = (
            CHANGE_REQUEST_METHOD_ENABLED == "True"
            if isinstance(CHANGE_REQUEST_METHOD_ENABLED, str)
            else bool(CHANGE_REQUEST_METHOD_ENABLED)
        )
        self.request_method_from = (REQUEST_METHOD_FROM or "").upper().strip()
        self.request_method_to = (REQUEST_METHOD_TO or "").upper().strip()

        self.redirect_request_enabled = (
            REDIRECT_REQUEST_ENABLED == "True"
            if isinstance(REDIRECT_REQUEST_ENABLED, str)
            else bool(REDIRECT_REQUEST_ENABLED)
        )
        self.redirect_to_host = (REDIRECT_TO_HOST or "").strip()
        try:
            if isinstance(REDIRECT_TO_PORT, str):
                self.redirect_to_port = int(REDIRECT_TO_PORT) if REDIRECT_TO_PORT.strip() else 0
            else:
                self.redirect_to_port = int(REDIRECT_TO_PORT)
        except (TypeError, ValueError):
            self.redirect_to_port = 0

        self.rewrite_url_enabled = (
            REWRITE_URL_ENABLED == "True"
            if isinstance(REWRITE_URL_ENABLED, str)
            else bool(REWRITE_URL_ENABLED)
        )
        self.url_rewrite_pattern = (URL_REWRITE_PATTERN or "").strip()
        self.url_rewrite_with = (URL_REWRITE_WITH or "").replace("\\n", "\n")
        self.url_rewrite_regex = (
            re.compile(self.url_rewrite_pattern) if self.url_rewrite_pattern else None
        )


        # Response mods
        self.add_resp_headers_enabled = (
            ADD_RESP_HEADERS_ENABLED == "True"
            if isinstance(ADD_RESP_HEADERS_ENABLED, str)
            else bool(ADD_RESP_HEADERS_ENABLED)
        )
        self.resp_headers_to_add = _parse_header_lines(str(RESP_HEADERS_TO_ADD))

        self.remove_resp_headers_enabled = (
            REMOVE_RESP_HEADERS_ENABLED == "True"
            if isinstance(REMOVE_RESP_HEADERS_ENABLED, str)
            else bool(REMOVE_RESP_HEADERS_ENABLED)
        )
        self.resp_headers_to_remove = _parse_header_names(str(RESP_HEADERS_TO_REMOVE))

        self.replace_response_body_enabled = (
            REPLACE_RESPONSE_BODY_ENABLED == "True"
            if isinstance(REPLACE_RESPONSE_BODY_ENABLED, str)
            else bool(REPLACE_RESPONSE_BODY_ENABLED)
        )
        self.resp_body_replace_pattern = (RESP_BODY_REPLACE_PATTERN or "").strip()
        self.resp_body_replace_with = (RESP_BODY_REPLACE_WITH or "").replace("\\n", "\n")
        self.resp_body_regex = (
            re.compile(self.resp_body_replace_pattern) if self.resp_body_replace_pattern else None
        )

        self.inject_html_js_enabled = (
            INJECT_HTML_JS_ENABLED == "True"
            if isinstance(INJECT_HTML_JS_ENABLED, str)
            else bool(INJECT_HTML_JS_ENABLED)
        )
        self.html_js_injection_code = str(HTML_JS_INJECTION_CODE or "")

                # Modify cookies
        self.modify_cookies_enabled = (
            MODIFY_COOKIES_ENABLED == "True"
            if isinstance(MODIFY_COOKIES_ENABLED, str)
            else bool(MODIFY_COOKIES_ENABLED)
        )
        # cookie_modifications: multi-line rules
        self.cookie_rules = _split_nonempty_lines(str(COOKIE_MODIFICATIONS))

        # Change status code mapping
        self.change_status_code_enabled = (
            CHANGE_STATUS_CODE_ENABLED == "True"
            if isinstance(CHANGE_STATUS_CODE_ENABLED, str)
            else bool(CHANGE_STATUS_CODE_ENABLED)
        )
        try:
            self.status_code_from = int(STATUS_CODE_FROM) if str(STATUS_CODE_FROM).strip() else 0
        except (TypeError, ValueError):
            self.status_code_from = 0  # 0 = ANY original status

        try:
            self.status_code_to = int(STATUS_CODE_TO) if str(STATUS_CODE_TO).strip() else 0
        except (TypeError, ValueError):
            self.status_code_to = 0  # 0 = disabled



        if self.log_to_file:
            configure_file_logging(self.log_file_path)

                # -------- Advanced & Utility Features --------
        # Auto auth
        self.auto_handle_auth_enabled = (
            AUTO_HANDLE_AUTH_ENABLED == "True"
            if isinstance(AUTO_HANDLE_AUTH_ENABLED, str)
            else bool(AUTO_HANDLE_AUTH_ENABLED)
        )
        self.auth_token = (AUTH_TOKEN or "").strip()

        # Replay (educational stub)
        self.replay_attack_enabled = (
            REPLAY_ATTACK_ENABLED == "True"
            if isinstance(REPLAY_ATTACK_ENABLED, str)
            else bool(REPLAY_ATTACK_ENABLED)
        )
        try:
            self.replay_count = int(REPLAY_COUNT) if str(REPLAY_COUNT).strip() else 1
        except (TypeError, ValueError):
            self.replay_count = 1
        if self.replay_count < 1:
            self.replay_count = 1

        # Auto scan toggle
        self.enable_auto_scan = (
            ENABLE_AUTO_SCAN == "True"
            if isinstance(ENABLE_AUTO_SCAN, str)
            else bool(ENABLE_AUTO_SCAN)
        )

        # Global custom headers (multi-line "Header: value")
        self.global_headers_to_add = _parse_header_lines(str(CUSTOM_HEADERS_GLOBAL))

        # Custom crypto flags (wired but NOT executed for safety)
        self.custom_decrypt_function_enabled = (
            CUSTOM_DECRYPT_FUNCTION_ENABLED == "True"
            if isinstance(CUSTOM_DECRYPT_FUNCTION_ENABLED, str)
            else bool(CUSTOM_DECRYPT_FUNCTION_ENABLED)
        )
        self.decrypt_function_code = str(DECRYPT_FUNCTION_CODE or "")

        self.custom_encrypt_function_enabled = (
            CUSTOM_ENCRYPT_FUNCTION_ENABLED == "True"
            if isinstance(CUSTOM_ENCRYPT_FUNCTION_ENABLED, str)
            else bool(CUSTOM_ENCRYPT_FUNCTION_ENABLED)
        )
        self.encrypt_function_code = str(ENCRYPT_FUNCTION_CODE or "")


        logger.info(
            f"Proxy2 initialized domain={self.target_domain}, "
            f"algorithm={self.algorithm}, "
            f"encrypt_to_server={self.encrypt_to_server}, "
            f"decrypt_from_server={self.decrypt_from_server}, "
            f"allowed_methods={self.allowed_methods or 'ANY'}, "
            f"log_to_file={self.log_to_file}, "
            f"rate_limit_qps={self.rate_limit_qps}, "
            f"regex_pattern={'set' if self.regex_pattern else 'none'}, "
            f"block_enabled={self.block_enabled}, "
            f"auto_handle_auth={self.auto_handle_auth_enabled}, "
            f"replay_attack_enabled={self.replay_attack_enabled}, "
            f"enable_auto_scan={self.enable_auto_scan}"
        )


    # -------------------------
    # Helper: rate limit
    # -------------------------
    def _allow_processing(self) -> bool:
        if not self.rate_limiter:
            return True
        allowed = self.rate_limiter.allow()
        if not allowed:
            logger.debug("Proxy2: rate limit hit, skipping heavy processing for this flow.")
        return allowed

        # -------------------------
    # Targeting helpers
    # -------------------------
    def _request_matches_filters(self, flow: http.HTTPFlow, body_text: str) -> bool:
        """
        Return True jika request ini memenuhi semua filter yang diaktifkan.
        Jika tidak ada filter yang aktif, selalu True.
        """
        # Domain filter
        if self.filter_by_domain and self.filter_domain_regex:
            host = flow.request.host or ""
            if not self.filter_domain_regex.search(host):
                return False

        # URL path filter
        if self.filter_by_url_path and self.filter_url_path_regex:
            path = flow.request.path or flow.request.url
            if not self.filter_url_path_regex.search(path):
                return False

        # HTTP method filter (toggle + allowed_methods list)
        if self.filter_by_http_method and self.allowed_methods:
            if flow.request.method.upper() not in self.allowed_methods:
                return False

        # Request header filter
        if self.filter_by_request_header and self.filter_request_header_name:
            name = self.filter_request_header_name
            headers = flow.request.headers
            if name not in headers:
                return False
            if self.filter_request_header_value:
                value = headers.get(name, "")
                regex = self.filter_request_header_value_regex
                if regex and not regex.search(value):
                    return False

        # Body content filter
        if self.filter_by_body_content and self.filter_body_regex:
            if not self.filter_body_regex.search(body_text or ""):
                return False

        # Client IP filter
        if self.filter_by_client_ip and self.filter_client_ip_regex:
            client_ip = ""
            try:
                if flow.client_conn and flow.client_conn.peername:
                    client_ip = flow.client_conn.peername[0]
            except Exception:
                client_ip = ""
            if not self.filter_client_ip_regex.search(client_ip):
                return False

        return True

    def _response_matches_filters(self, flow: http.HTTPFlow) -> bool:
        """
        Simple filter untuk response berdasarkan header.
        (Body filter saat ini hanya dipakai di request side.)
        """
        if self.filter_by_response_header and self.filter_response_header_name:
            name = self.filter_response_header_name
            headers = flow.response.headers
            if name not in headers:
                return False
            if self.filter_response_header_value:
                value = headers.get(name, "")
                regex = self.filter_response_header_value_regex
                if regex and not regex.search(value):
                    return False
        return True


    # -------------------------
    # Internal helpers
    # -------------------------
    def _maybe_block_request(self, flow: http.HTTPFlow, body_text: str) -> bool:
        """
        Returns True if the request was blocked and a response was set.
        """
        if not (self.block_enabled and self.block_regex):
            return False

        target_text = f"{flow.request.method} {flow.request.url}\n{body_text or ''}"
        if self.block_regex.search(target_text):
            logger.warning("Proxy2: blocking request by regex rule.")
            flow.response = http.Response.make(
                403,
                b"Blocked by Proxy2: rule matched.",
                {"Content-Type": "text/plain"},
            )
            return True
        return False

    def _apply_cookie_mods(self, flow: http.HTTPFlow) -> None:
        """
        Modify response cookies based on simple text rules.

        Format aturan di UI (cookieModifications, multi-line):

        - "set name=value"    -> set / override cookie 'name' dengan 'value'
        - "delete name"       -> hapus cookie 'name' dari response

        Contoh:
            set sessionid=ABC123
            delete tracking_id
        """
        if not (self.modify_cookies_enabled and self.cookie_rules and flow.response):
            return

        for rule in self.cookie_rules:
            line = rule.strip()
            if not line:
                continue
            lower = line.lower()

            if lower.startswith("set "):
                kv = line[4:].strip()
                if "=" in kv:
                    name, val = kv.split("=", 1)
                    name = name.strip()
                    val = val.strip()
                    if name:
                        flow.response.cookies[name] = val
                        logger.info(f"Proxy2: set cookie {name}={val}")
            elif lower.startswith("delete "):
                name = line[7:].strip()
                if name and name in flow.response.cookies:
                    try:
                        del flow.response.cookies[name]
                        logger.info(f"Proxy2: deleted cookie {name}")
                    except Exception as exc:
                        logger.warning(f"Proxy2: failed to delete cookie {name}: {exc}")


    def _apply_request_header_mods(self, flow: http.HTTPFlow) -> None:
        if self.add_req_headers_enabled:
            for name, val in self.req_headers_to_add:
                flow.request.headers[name] = val
        if self.remove_req_headers_enabled:
            for name in self.req_headers_to_remove:
                if name in flow.request.headers:
                    del flow.request.headers[name]

        # NEW: User-Agent & Host rewrite
        if self.modify_user_agent_enabled and self.custom_user_agent:
            flow.request.headers["User-Agent"] = self.custom_user_agent

        if self.modify_host_header_enabled and self.custom_host_header:
            flow.request.headers["Host"] = self.custom_host_header

        # NEW: Global custom headers (Advanced)
        if self.global_headers_to_add:
            for name, val in self.global_headers_to_add:
                # Jangan timpa kalau sudah di-set oleh aturan lain (kecuali kamu mau override)
                if name not in flow.request.headers:
                    flow.request.headers[name] = val

        # NEW: Auto auth (Authorization header)
        if self.auto_handle_auth_enabled and self.auth_token:
            if "Authorization" not in flow.request.headers:
                flow.request.headers["Authorization"] = self.auth_token
                logger.info("Proxy2: autoHandleAuth applied Authorization header.")

    def _apply_advanced_request_mods(self, flow: http.HTTPFlow, body_text: str) -> None:
       
        # Change request method
        if self.change_request_method_enabled and self.request_method_from:
            if flow.request.method.upper() == self.request_method_from:
                new_method = self.request_method_to or flow.request.method
                flow.request.method = new_method.upper()
                logger.info(
                    f"Proxy2: changed request method from {self.request_method_from} "
                    f"to {flow.request.method} for {flow.request.url}"
                )

        # Redirect to another host/port
        if self.redirect_request_enabled and self.redirect_to_host:
            old_host, old_port = flow.request.host, flow.request.port
            flow.request.host = self.redirect_to_host
            if self.redirect_to_port:
                flow.request.port = self.redirect_to_port

            # Sync Host header if user didn't explicitly override it
            if not (self.modify_host_header_enabled and self.custom_host_header):
                flow.request.headers["Host"] = self.redirect_to_host

            logger.info(
                f"Proxy2: redirecting request from {old_host}:{old_port} "
                f"to {flow.request.host}:{flow.request.port}"
            )

        # Rewrite URL/path via regex
        if self.rewrite_url_enabled and self.url_rewrite_regex:
            try:
                old_path = flow.request.path
                new_path = self.url_rewrite_regex.sub(self.url_rewrite_with, old_path)
                if new_path != old_path:
                    flow.request.path = new_path
                    logger.info(
                        f"Proxy2: rewrote URL path from {old_path!r} to {new_path!r} "
                        f"for {flow.request.method} {flow.request.host}"
                    )
            except re.error as exc:
                logger.warning(f"Proxy2: URL rewrite regex error: {exc}")


    def _apply_request_body_mod(self, body_text: str) -> str:
        if self.replace_request_body_enabled and self.req_body_regex:
            return self.req_body_regex.sub(self.req_body_replace_with, body_text)
        return body_text

    def _apply_response_header_mods(self, flow: http.HTTPFlow) -> None:
        if self.add_resp_headers_enabled:
            for name, val in self.resp_headers_to_add:
                flow.response.headers[name] = val
        if self.remove_resp_headers_enabled:
            for name in self.resp_headers_to_remove:
                if name in flow.response.headers:
                    del flow.response.headers[name]

    def _apply_response_body_mod(self, body_text: str) -> str:
        updated = body_text
        if self.replace_response_body_enabled and self.resp_body_regex:
            updated = self.resp_body_regex.sub(self.resp_body_replace_with, updated)

        if self.inject_html_js_enabled and self.html_js_injection_code and "<html" in updated.lower():
            # naive HTML inject before </body>
            lower = updated.lower()
            idx = lower.rfind("</body>")
            snippet = self.html_js_injection_code
            if idx != -1:
                updated = updated[:idx] + snippet + updated[idx:]
            else:
                updated = updated + snippet
        return updated

    # -------------------------
    # mitmproxy hooks
    # -------------------------
    def request(self, flow: http.HTTPFlow) -> None:
        # Burp → Proxy2 → Server
        if flow.request.host == "127.0.0.1" and flow.request.method == "SHUTDOWN":
            if self.master is not None:
                logger.warning("Proxy2: SHUTDOWN requested, stopping master.")
                self.master.shutdown()
            return

        if flow.request.host != self.target_domain:
            return

        if not self._allow_processing():
            # Let traffic pass untouched if rate-limited
            return

        method = flow.request.method.upper()

        # Method filtering
        if self.allowed_methods and method not in self.allowed_methods:
            logger.warning(f"Proxy2: blocking disallowed method {method} to {flow.request.url}")
            flow.response = http.Response.make(
                403,
                b"Blocked by Proxy2: HTTP method not allowed.",
                {"Content-Type": "text/plain"},
            )
            return

        try:
            body, enc = get_request_body(flow)
            if not body:
                body = b""

            text = body.decode("utf-8", errors="replace")

            # Targeting & filtering: jika tidak match filter, biarkan lewat tanpa diproses
            if not self._request_matches_filters(flow, text):
                logger.debug("Proxy2: request does not match filters, forwarding without processing.")
                return

            # Block / drop based on regex
            if self._maybe_block_request(flow, text):
                return
           
            # Apply header & body modifications on plaintext
            self._apply_request_header_mods(flow)
            if self.replace_request_body_enabled and self.req_body_regex:
                text = self._apply_request_body_mod(text)
                body = text.encode("utf-8", errors="replace")

            self._apply_advanced_request_mods(flow, text)

            summary = pretty_flow_summary(
                flow.request.method, flow.request.url, dict(flow.request.headers), body
            )
            logger.debug("Proxy2 plaintext request summary:\n" + summary)

            if self.enable_auto_scan:
                secrets = scan_secrets(text)
                if secrets:
                    logger.info(f"Proxy2: secrets detected in plaintext request: {secrets}")

            # Optional regex extraction on request
            if self.enable_auto_scan and self.regex_compiled and self.regex_file:
                try:
                    count = extract_and_save(self.regex_pattern, text, self.regex_file)
                    if count:
                        logger.info(
                            f"Proxy2: regex extracted {count} items from request into {self.regex_file}"
                        )
                except Exception as exc:
                    logger.warning(f"Proxy2: regex extraction error (request): {exc}")

                        # If we are NOT encrypting to server, just forward any modified plaintext
            if not self.encrypt_to_server:
                logger.debug("Proxy2: encrypt_to_server=False, forwarding plaintext to server.")
                if body:
                    set_request_body(flow, body, enc)
                return

            # If this is NOT a credential request, fall back to old full-body encrypt (if you still want it)
            if not self._is_credential_request(flow):
                logger.debug("Proxy2: non-credential request, forwarding plaintext without encryption.")
                if body:
                    set_request_body(flow, body, enc)
                return

                        # ---- CREDENTIAL-ONLY RE-ENCRYPTION ----
            logger.info(f"Proxy2: re-encrypting credentials for {flow.request.method} {flow.request.url}")

            content_type = flow.request.headers.get("Content-Type", "")
            text = body.decode("utf-8", errors="replace")

             # Case 1: JSON body with plaintext creds from Burp
            if "application/json" in content_type:
                try:
                    data = json.loads(text)
                except Exception as exc:
                    logger.warning(
                        f"Proxy2: JSON parse error during re-encrypt: {exc}, forwarding plaintext."
                    )
                    if body:
                        set_request_body(flow, body, enc)
                    return

                username_pt = data.get("username")
                password_pt = data.get("password")

                if not username_pt and not password_pt:
                    logger.debug(
                        "Proxy2: JSON body has no username/password, forwarding plaintext."
                    )
                    if body:
                        set_request_body(flow, body, enc)
                    return

                # ==========================
                # ENCRYPT HANYA FIELD CREDENTIAL
                # ==========================
                if CREDENTIAL_FORMAT == "b64_block":
                    # Mode lama: username/password = base64(iv||ct)
                    if username_pt is not None:
                        data["username"] = self._encrypt_field_b64_block(username_pt)
                    if password_pt is not None:
                        data["password"] = self._encrypt_field_b64_block(password_pt)

                elif CREDENTIAL_FORMAT == "hex_iv_split":
                    # Mode Flask: username/password hex + iv/ivpw hex
                    if username_pt is not None:
                        ct_u, iv_u = self._encrypt_field_hex_with_iv(username_pt)
                        data["username"] = ct_u
                        data["iv"] = iv_u
                    if password_pt is not None:
                        ct_p, iv_p = self._encrypt_field_hex_with_iv(password_pt)
                        data["password"] = ct_p
                        data["ivpw"] = iv_p

                else:
                    logger.warning(
                        f"Proxy2: unknown CREDENTIAL_FORMAT={CREDENTIAL_FORMAT!r}, forwarding plaintext."
                    )
                    if body:
                        set_request_body(flow, body, enc)
                    return

                new_text = json.dumps(data)
                new_body = new_text.encode("utf-8", errors="replace")
                set_request_body(flow, new_body, enc)
                logger.info(
                    "Proxy2: credentials re-encrypted in JSON and forwarded to server."
                )
                return


        # Case 2: Form body: username=alice&password=secret
            if "application/x-www-form-urlencoded" in content_type:
                from urllib.parse import parse_qs, urlencode

                params = parse_qs(text, keep_blank_values=True)
                username_pt = (params.get("username") or [""])[0]
                password_pt = (params.get("password") or [""])[0]

                if not username_pt and not password_pt:
                    logger.debug(
                        "Proxy2: form body has no username/password, forwarding plaintext."
                    )
                    if body:
                        set_request_body(flow, body, enc)
                    return

                if CREDENTIAL_FORMAT == "b64_block":
                    if username_pt:
                        params["username"] = [self._encrypt_field_b64_block(username_pt)]
                    if password_pt:
                        params["password"] = [self._encrypt_field_b64_block(password_pt)]

                elif CREDENTIAL_FORMAT == "hex_iv_split":
                    # Ambil IV kalau sudah ada, kalau tidak kita isi yang baru
                    if username_pt:
                        ct_u, iv_u = self._encrypt_field_hex_with_iv(username_pt)
                        params["username"] = [ct_u]
                        params["iv"] = [iv_u]
                    if password_pt:
                        ct_p, iv_p = self._encrypt_field_hex_with_iv(password_pt)
                        params["password"] = [ct_p]
                        params["ivpw"] = [iv_p]

                else:
                    logger.warning(
                        f"Proxy2: unknown CREDENTIAL_FORMAT={CREDENTIAL_FORMAT!r}, forwarding plaintext."
                    )
                    if body:
                        set_request_body(flow, body, enc)
                    return

                new_text = urlencode(params, doseq=True)
                new_body = new_text.encode("utf-8", errors="replace")
                set_request_body(flow, new_body, enc)
                logger.info(
                    "Proxy2: credentials re-encrypted in form and forwarded to server."
                )
                return


        except Exception as exc:
            logger.warning(f"Proxy2 request error: {exc}")

    def response(self, flow: http.HTTPFlow) -> None:
        # Server → Proxy2 → Burp
        if flow.request.host != self.target_domain:
            return
        if not flow.response:
            return

        if not self._allow_processing():
            # Let traffic pass untouched if rate-limited
            return

        try:
            body, enc = get_response_body(flow)
            if not body:
                logger.debug("Proxy2: empty response body, nothing to decrypt.")
                return

            if not self.decrypt_from_server:
                logger.debug("Proxy2: decrypt_from_server=False, forwarding encrypted response.")
                return

            logger.info(f"Proxy2: decrypting response for {flow.request.method} {flow.request.url}")

            plaintext = decrypt(body, algorithm=self.algorithm, key=self.key)
            text = plaintext.decode("utf-8", errors="replace")

             # Response-level filter (by header)
            if not self._response_matches_filters(flow):
                # tetap forward plaintext ke Burp tanpa modifikasi tambahan
                set_response_body(flow, plaintext, enc)
                logger.debug("Proxy2: response does not match filters, forwarded without modification.")
                return

            summary = pretty_flow_summary(
                flow.request.method, flow.request.url, dict(flow.response.headers), plaintext
            )
            logger.debug("Proxy2 decrypted response summary:\n" + summary)

            if self.enable_auto_scan:
                secrets = scan_secrets(text)
                if secrets:
                    logger.info(f"Proxy2: secrets detected in decrypted response: {secrets}")

            # Optional regex extraction on decrypted response
            if self.enable_auto_scan and self.regex_compiled and self.regex_file:
                try:
                    count = extract_and_save(self.regex_pattern, text, self.regex_file)
                    if count:
                        logger.info(
                            f"Proxy2: regex extracted {count} items from response into {self.regex_file}"
                        )
                except Exception as exc:
                    logger.warning(f"Proxy2: regex extraction error (response): {exc}")

            # NEW: cookie modifications
            self._apply_cookie_mods(flow)
            
            # Response header/body modifications
            
            self._apply_response_header_mods(flow)
            if self.replace_response_body_enabled or self.inject_html_js_enabled:
                text = self._apply_response_body_mod(text)
                plaintext = text.encode("utf-8", errors="replace")

            # Change status code (if enabled and valid)
            if self.change_status_code_enabled and self.custom_status_code:
                logger.info(
                    f"Proxy2: changing response status code "
                    f"from {flow.response.status_code} to {self.custom_status_code}"
                )
                flow.response.status_code = self.custom_status_code

            set_response_body(flow, plaintext, enc)

            logger.info("Proxy2: response body decrypted and forwarded to Burp.")


        except Exception as exc:
            logger.warning(f"Proxy2 response error: {exc}")


# -------------------------
# CLI helpers (optional)
# -------------------------

async def start_proxy(
    listen_host: str = "0.0.0.0",
    listen_port: int = 8084,
    target_domain: str = TARGET_DOMAIN,
    algorithm: str = ALGORITHM,
    key: str = KEY,
    encrypt_to_server: bool = ENCRYPT_TO_SERVER,
    decrypt_from_server: bool = DECRYPT_FROM_SERVER,
) -> DumpMaster:
    

    """
    Start mitmdump-compatible proxy for manual use.
    """
    opts = options.Options(listen_host=listen_host, listen_port=listen_port,ssl_insecure=True,)
    master = DumpMaster(opts)

    # If you want CLI to override defaults, you can pass them here:
    proxy = Proxy2(
        master=master,
        target_domain=target_domain,
        algorithm=algorithm,
        key=key,
        encrypt_to_server=encrypt_to_server,
        decrypt_from_server=decrypt_from_server,
    )
    master.addons.add(proxy)

    logger.info(f"[Proxy2] Starting on {listen_host}:{listen_port} for {target_domain}")
    try:
        await master.run()
    finally:
        logger.info("[Proxy2] Stopped.")
    return master


# For mitmdump:
addons = [Proxy2()]

if __name__ == "__main__":
    asyncio.run(start_proxy())
