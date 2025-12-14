# script1.py  (TEMPLATE)

import json
import base64

from typing import Optional

import asyncio
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

# These are placeholders replaced by app.py before download:
TARGET_DOMAIN = "__TARGET_DOMAIN__"
ALGORITHM = "__ALGORITHM__"
KEY = __KEY__

DECRYPT_CLIENT_REQUESTS = "__DECRYPT_CLIENT_REQUESTS__"
ENCRYPT_CLIENT_RESPONSES = "__ENCRYPT_CLIENT_RESPONSES__"

# "b64_block"   -> username/password = base64(iv||ct)
# "hex_iv_split" -> username/password hex + iv/ivpw hex (your current site)
CREDENTIAL_FORMAT = "__CREDENTIAL_FORMAT__"

# Optional logging flags (can be left as-is if not used)
LOG_TO_FILE = "__LOG_TO_FILE__"
LOG_FILE_PATH = "__LOG_FILE_PATH__"

# Optional regex extraction / rate limit (wired from UI)
REGEX_EXTRACT_PATTERN = "__REGEX_EXTRACT_PATTERN__"
REGEX_EXTRACT_FILE = "__REGEX_EXTRACT_FILE__"
RATE_LIMIT_QPS = "__RATE_LIMIT_QPS__"


class Proxy1:
    """
    Client-side decryption/encryption proxy.
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

    def _decrypt_field_b64_block(self, value: str) -> str:
        """
        Decrypt base64(iv||ct) → plaintext.
        """
        if not value:
            return value
        try:
            ciphertext = base64.b64decode(value)
            plaintext = decrypt(ciphertext, algorithm=self.algorithm, key=self.key)
            return plaintext.decode("utf-8", errors="replace")
        except Exception as exc:
            logger.warning(f"Proxy1: failed to decrypt base64 field: {exc}")
            return value

    def _decrypt_field_hex_with_iv(self, ct_hex: str, iv_hex: str) -> str:
        """
        Decrypt hex ciphertext with separate hex IV (your current website format).
        We rebuild iv||ct, then call util.decrypt().
        """
        if not ct_hex or not iv_hex:
            return ct_hex
        try:
            ct = bytes.fromhex(ct_hex)
            iv = bytes.fromhex(iv_hex)
            combined = iv + ct
            plaintext = decrypt(combined, algorithm=self.algorithm, key=self.key)
            return plaintext.decode("utf-8", errors="replace")
        except Exception as exc:
            logger.warning(f"Proxy1: failed to decrypt hex+iv field: {exc}")
            return ct_hex


    def __init__(
        self,
        master: Optional[DumpMaster] = None,
        target_domain: str = TARGET_DOMAIN,
        algorithm: str = ALGORITHM,
        key: str = KEY,
        decrypt_client_requests: Optional[bool] = DECRYPT_CLIENT_REQUESTS,
        encrypt_client_responses: Optional[bool] = ENCRYPT_CLIENT_RESPONSES,
        log_to_file: Optional[bool] = LOG_TO_FILE,
        log_file_path: str = LOG_FILE_PATH,
        regex_pattern: str = REGEX_EXTRACT_PATTERN,
        regex_file: str = REGEX_EXTRACT_FILE,
        rate_limit_qps: float = RATE_LIMIT_QPS,
    ):
        if isinstance(decrypt_client_requests, str):
            decrypt_client_requests = decrypt_client_requests == "True"
        if isinstance(encrypt_client_responses, str):
            encrypt_client_responses = encrypt_client_responses == "True"
        if isinstance(log_to_file, str):
            log_to_file = log_to_file == "True"
        if isinstance(rate_limit_qps, str):
            try:
                rate_limit_qps = float(rate_limit_qps)
            except ValueError:
                rate_limit_qps = 0.0

        self.master = master
        self.target_domain = target_domain
        self.algorithm = algorithm
        self.key = key
        self.decrypt_client_requests = bool(decrypt_client_requests)
        self.encrypt_client_responses = bool(encrypt_client_responses)
        self.log_to_file = bool(log_to_file)
        self.log_file_path = log_file_path or "./proxy1_logs.txt"

        self.regex_pattern = (regex_pattern or "").strip()
        self.regex_file = (regex_file or "").strip()
        self.regex_compiled = (
            __import__("re").compile(self.regex_pattern) if self.regex_pattern else None
        )

        self.rate_limit_qps = float(rate_limit_qps) if rate_limit_qps else 0.0
        self.rate_limiter = SimpleRateLimiter(self.rate_limit_qps) if self.rate_limit_qps > 0 else None

        if self.log_to_file:
            configure_file_logging(self.log_file_path)

        logger.info(
            f"Proxy1 initialized domain={self.target_domain}, "
            f"algorithm={self.algorithm}, "
            f"decrypt_req={self.decrypt_client_requests}, "
            f"encrypt_resp={self.encrypt_client_responses}, "
            f"log_to_file={self.log_to_file}, "
            f"rate_limit_qps={self.rate_limit_qps}, "
            f"regex_pattern={'set' if self.regex_pattern else 'none'}"
        )

    # -------------------------
    # Helper: rate limit
    # -------------------------
    def _allow_processing(self) -> bool:
        if not self.rate_limiter:
            return True
        allowed = self.rate_limiter.allow()
        if not allowed:
            logger.debug("Proxy1: rate limit hit, skipping heavy processing for this flow.")
        return allowed

    # -------------------------
    # mitmproxy hooks
    # -------------------------
    def request(self, flow: http.HTTPFlow) -> None:
        # Client → Proxy1 → Burp

        # Special SHUTDOWN convenience endpoint
        if flow.request.host == "127.0.0.1" and flow.request.method == "SHUTDOWN":
            if self.master is not None:
                logger.warning("Proxy1: SHUTDOWN requested, stopping master.")
                self.master.shutdown()
            return

        # We only care about our victim domain
        if flow.request.host != self.target_domain:
            return

        if not self._allow_processing():
            return

        # If decryption is disabled, just let it pass
        if not self.decrypt_client_requests:
            logger.debug("Proxy1: decrypt_client_requests=False, forwarding as-is.")
            return

        # Only process credential requests
        if not self._is_credential_request(flow):
            return

        try:
            body, enc = get_request_body(flow)
            if not body:
                logger.debug("Proxy1: empty request body, nothing to decrypt.")
                return

            content_type = flow.request.headers.get("Content-Type", "")
            text = body.decode("utf-8", errors="replace")

            logger.info(f"Proxy1: decrypting credentials for {flow.request.method} {flow.request.url}")

            # Case 1: JSON body containing encrypted credentials
            if "application/json" in content_type:
                try:
                    data = json.loads(text)
                except Exception as exc:
                    logger.warning(f"Proxy1: JSON parse error: {exc}")
                    return

                username_ct = data.get("username")
                password_ct = data.get("password")

                if not username_ct and not password_ct:
                    # No credentials → do nothing
                    return

                # ==========================
                # CREDENTIAL FORMAT HANDLING
                # ==========================

                if CREDENTIAL_FORMAT == "b64_block":
                    username_pt = (
                        self._decrypt_field_b64_block(username_ct)
                            if username_ct else None
                    )
                    password_pt = (
                        self._decrypt_field_b64_block(password_ct)
                            if password_ct else None
                    )

                elif CREDENTIAL_FORMAT == "hex_iv_split":
                    iv_user = data.get("iv") or ""
                    iv_pw = data.get("ivpw") or ""
                    username_pt = (
                        self._decrypt_field_hex_with_iv(username_ct, iv_user)
                            if username_ct and iv_user else None
                    )
                    password_pt = (
                        self._decrypt_field_hex_with_iv(password_ct, iv_pw)
                            if password_ct and iv_pw else None
                    )

                else:
                    logger.warning(f"Proxy1: unknown CREDENTIAL_FORMAT={CREDENTIAL_FORMAT!r}")
                    username_pt = username_ct
                    password_pt = password_ct

                # ==========================
                # REPLACE FOR BURP INTERCEPT
                # ==========================

                if username_pt is not None:
                    data["username"] = username_pt
                if password_pt is not None:
                    data["password"] = password_pt

                new_text = json.dumps(data)
                new_body = new_text.encode("utf-8", errors="replace")
                set_request_body(flow, new_body, enc)

                logger.info(f"Proxy1: decrypted JSON creds for BURP: {username_pt!r} | {password_pt!r}")
                return


            # Case 2: FORM body containing encrypted credentials
            if "application/x-www-form-urlencoded" in content_type:
                from urllib.parse import parse_qs, urlencode

                params = parse_qs(text, keep_blank_values=True)

                username_ct = (params.get("username") or [""])[0]
                password_ct = (params.get("password") or [""])[0]

                if not username_ct and not password_ct:
                    # No credentials → forward plaintext
                    return

                # ==========================
                # CREDENTIAL FORMAT HANDLING
                # ==========================

                if CREDENTIAL_FORMAT == "b64_block":
                    username_pt = (
                        self._decrypt_field_b64_block(username_ct)
                            if username_ct else None
                    )
                    password_pt = (
                        self._decrypt_field_b64_block(password_ct)
                            if password_ct else None
                    )

                elif CREDENTIAL_FORMAT == "hex_iv_split":
                    iv_user = (params.get("iv") or [""])[0]
                    iv_pw   = (params.get("ivpw") or [""])[0]

                    username_pt = (
                        self._decrypt_field_hex_with_iv(username_ct, iv_user)
                            if username_ct and iv_user else None
                    )
                    password_pt = (
                        self._decrypt_field_hex_with_iv(password_ct, iv_pw)
                            if password_ct and iv_pw else None
                    )

                else:
                    logger.warning(f"Proxy1: unknown CREDENTIAL_FORMAT={CREDENTIAL_FORMAT!r}")
                    username_pt = username_ct
                    password_pt = password_ct

                # ==========================
                # REPLACE FOR BURP INTERCEPT
                # ==========================

                if username_pt is not None:
                    params["username"] = [username_pt]
                if password_pt is not None:
                    params["password"] = [password_pt]

                new_text = urlencode(params, doseq=True)
                new_body = new_text.encode("utf-8", errors="replace")
                set_request_body(flow, new_body, enc)

                logger.info(f"Proxy1: decrypted FORM creds for BURP: {username_pt!r} | {password_pt!r}")
                return



        except Exception as exc:
            logger.warning(f"Proxy1 request error: {exc}")


async def start_proxy(
    listen_host: str = "0.0.0.0",
    listen_port: int = 8083,
    target_domain: str = TARGET_DOMAIN,
    algorithm: str = ALGORITHM,
    key: str = KEY,
    decrypt_client_requests: bool = DECRYPT_CLIENT_REQUESTS,
    encrypt_client_responses: bool = ENCRYPT_CLIENT_RESPONSES,
) -> DumpMaster:
    

    """
    Start mitmdump-compatible proxy for manual use.
    """
    opts = options.Options(listen_host=listen_host, listen_port=listen_port,ssl_insecure=True,)
    master = DumpMaster(opts)

    proxy = Proxy1(
        master=master,
        target_domain=target_domain,
        algorithm=algorithm,
        key=key,
        decrypt_client_requests=decrypt_client_requests,
        encrypt_client_responses=encrypt_client_responses,
    )
    master.addons.add(proxy)

    logger.info(f"[Proxy1] Starting on {listen_host}:{listen_port} for {target_domain}")
    try:
        await master.run()
    finally:
        logger.info("[Proxy1] Stopped.")
    return master


# For mitmdump:
addons = [Proxy1()]

if __name__ == "__main__":
    asyncio.run(start_proxy())
