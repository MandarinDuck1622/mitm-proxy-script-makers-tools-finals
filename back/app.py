# back/app.py

from flask import Flask, request, jsonify
from flask_cors import CORS
import os

app = Flask(__name__)
CORS(app)  # allow requests from your Next.js dev server

BASE_DIR = os.path.dirname(__file__)


def load_file(filename: str) -> str:
    """Read a text file from the back/ directory."""
    path = os.path.join(BASE_DIR, filename)
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


@app.route("/api/generate-scripts", methods=["POST"])
def generate_scripts():
    
    data = request.get_json(force=True, silent=True) or {}

    target_domain = data.get("targetDomain") or "localhost"
    algorithm = data.get("encryptionAlgorithm") or "aes-256-gcm"
    # use UI encryptionKey if exists, fallback to cryptoKey for older UIs
    key = (
        data.get("encryptionKey")
        or data.get("cryptoKey")
        or "0123456789abcdef0123456789abcdef"
    )

    # Key format from UI (optional)
    key_format = data.get("cryptoKeyFormat") or "text"


    # New: credential format from UI
    # "b64_block"  -> username/password = base64(iv||ct)
    # "hex_iv_split" -> your current website: username/password hex + iv/ivpw hex
    credential_format = data.get("credentialFormat") or "hex_iv_split"

    # Prepare key literal for script templates
    if key_format == "hex":
        key_literal = f"hex:{key.strip()}"
    else:
        key_literal = key


    enable_encryption = bool(data.get("enableEncryption"))
    enable_decryption = bool(data.get("enableDecryption"))

    decrypt_client_requests = enable_decryption
    encrypt_client_responses = enable_encryption

    encrypt_to_server = enable_encryption
    decrypt_from_server = False

    # HTTP method filter (optional)
    filter_methods = data.get("filterHttpMethods") or []
    allowed_methods = [m.upper() for m in filter_methods]
    if allowed_methods:
        allowed_methods_py = "[" + ",".join(f"'{m}'" for m in allowed_methods) + "]"
    else:
        allowed_methods_py = "[]"

        # Block / Drop requests (regex) from Advanced & Utility
    block_enabled = bool(data.get("blockRequests", False))
    block_pattern = data.get("blockRequestsPattern") or ""

        # -----------------------------
    # Targeting & Filtering from UI
    # -----------------------------
    filter_by_domain = bool(data.get("filterByDomain", False))
    filter_domain_pattern = data.get("filterDomainPattern") or ""

    filter_by_url_path = bool(data.get("filterByUrlPath", False))
    filter_url_path_pattern = data.get("filterUrlPathPattern") or ""

    # UI punya toggle filterByHttpMethod, di samping filterHttpMethods (list)
    filter_by_http_method = bool(data.get("filterByHttpMethod", False))

    filter_by_request_header = bool(data.get("filterByRequestHeader", False))
    filter_request_header_name = data.get("filterRequestHeaderName") or ""
    filter_request_header_value = data.get("filterRequestHeaderValue") or ""

    filter_by_response_header = bool(data.get("filterByResponseHeader", False))
    filter_response_header_name = data.get("filterResponseHeaderName") or ""
    filter_response_header_value = data.get("filterResponseHeaderValue") or ""

    filter_by_body_content = bool(data.get("filterByBodyContent", False))
    filter_body_content_pattern = data.get("filterBodyContentPattern") or ""

    filter_by_client_ip = bool(data.get("filterByClientIp", False))
    filter_client_ip_address = data.get("filterClientIpAddress") or ""


    # Logging (maps from logTraffic)
    log_to_file = bool(data.get("logTraffic", False))
    log_file_path = data.get("logFilePath") or "./proxy_traffic.log"

    # Regex extract (maps from extractSaveData / extractDataPattern)
    if data.get("extractSaveData"):
        regex_pattern = data.get("extractDataPattern") or ""
    else:
        regex_pattern = ""
    regex_output_file = "./extracted_data.txt"

    # Rate limit (string from frontend)
    raw_qps = data.get("rateLimitQps", 0)
    try:
        rate_limit_qps = float(raw_qps) if raw_qps not in (None, "") else 0.0
        if rate_limit_qps < 0:
            rate_limit_qps = 0.0
    except (TypeError, ValueError):
        rate_limit_qps = 0.0

    # --- New scripting features wired from UI ---

    # Block / Drop requests (regex)
    block_enabled = bool(data.get("blockRequests", False))
    block_pattern = data.get("blockRequestsPattern") or ""

    # Request header modifications
    add_req_headers_enabled = bool(data.get("addModifyRequestHeader", False))
    req_headers_to_add = data.get("requestHeadersToAdd") or ""

    remove_req_headers_enabled = bool(data.get("removeRequestHeader", False))
    req_headers_to_remove = data.get("requestHeadersToRemove") or ""

    replace_req_body_enabled = bool(data.get("replaceRequestBody", False))
    req_body_replace_pattern = data.get("requestBodyReplacePattern") or ""
    req_body_replace_with = data.get("requestBodyReplaceWith") or ""

        # -------- Advanced Request Mods (UA/Host/method/redirect/rewrite) ----------
    modify_user_agent_enabled = bool(data.get("modifyUserAgent", False))
    custom_user_agent = data.get("customUserAgent") or ""

    modify_host_header_enabled = bool(data.get("modifyHostHeader", False))
    custom_host_header = data.get("customHostHeader") or ""

    change_request_method_enabled = bool(data.get("changeRequestMethod", False))
    request_method_from = (data.get("requestMethodFrom") or "").upper()
    request_method_to = (data.get("requestMethodTo") or "").upper()

    redirect_request_enabled = bool(data.get("redirectRequest", False))
    redirect_to_host = data.get("redirectToHost") or ""
    redirect_to_port = data.get("redirectToPort") or ""
    try:
        redirect_to_port_int = int(redirect_to_port) if redirect_to_port not in (None, "") else 0
    except (TypeError, ValueError):
        redirect_to_port_int = 0

    rewrite_url_enabled = bool(data.get("rewriteUrl", False))
    url_rewrite_pattern = data.get("urlRewritePattern") or ""
    url_rewrite_with = data.get("urlRewriteWith") or ""


    # -------- Response header/body modifications ----------
    add_resp_headers_enabled = bool(data.get("addModifyResponseHeader", False))
    resp_headers_to_add = data.get("responseHeadersToAdd") or ""

    remove_resp_headers_enabled = bool(data.get("removeResponseHeader", False))
    resp_headers_to_remove = data.get("responseHeadersToRemove") or ""

    replace_resp_body_enabled = bool(data.get("replaceResponseBody", False))
    resp_body_replace_pattern = data.get("responseBodyReplacePattern") or ""
    resp_body_replace_with = data.get("responseBodyReplaceWith") or ""

    inject_html_js_enabled = bool(data.get("injectHtmlJs", False))
    html_js_injection_code = data.get("htmlJsInjectionCode") or ""

    # -------- Modify Cookies ----------
    modify_cookies_enabled = bool(data.get("modifyCookies", False))
    cookie_modifications = data.get("cookieModifications") or ""


        # -------- Advanced & Utility Features ----------
    auto_handle_auth = bool(data.get("autoHandleAuth", False))
    auth_token = data.get("authToken") or ""

    replay_attack_enabled = bool(data.get("replayAttack", False))
    raw_replay_count = data.get("replayCount")
    try:
        replay_count = int(raw_replay_count) if raw_replay_count not in (None, "") else 1
    except (TypeError, ValueError):
        replay_count = 1
    if replay_count < 1:
        replay_count = 1

    enable_auto_scan = bool(data.get("enableAutoScan", False))
    custom_headers_global = data.get("customHeaders") or ""

    custom_decrypt_function_enabled = bool(data.get("customDecryptFunction", False))
    decrypt_function_code = data.get("decryptFunctionCode") or ""

    custom_encrypt_function_enabled = bool(data.get("customEncryptFunction", False))
    encrypt_function_code = data.get("encryptFunctionCode") or ""


        # -------- Change status code (mapping from → to) ----------
    change_status_code_enabled = bool(data.get("changeStatusCode", False))
    raw_status_from = data.get("statusCodeFrom")
    raw_status_to = data.get("statusCodeTo")

    try:
        status_code_from = int(raw_status_from) if raw_status_from not in (None, "") else 0
    except (TypeError, ValueError):
        status_code_from = 0   # 0 = match ANY original status

    try:
        status_code_to = int(raw_status_to) if raw_status_to not in (None, "") else 0
    except (TypeError, ValueError):
        status_code_to = 0     # 0 = disabled / no-op

    # -----------------------------
    # Load script templates
    # -----------------------------
    script1_template = load_file("script1.py")
    script2_template = load_file("script2.py")
    util_code = load_file("util.py")

    # -----------------------------
    # Proxy1 generation (client-side)
    # -----------------------------
    proxy1_code = (
        script1_template
        .replace("__TARGET_DOMAIN__", target_domain)
        .replace("__ALGORITHM__", algorithm)
        .replace("__KEY__", repr(key_literal))
        .replace("__CREDENTIAL_FORMAT__", credential_format)
        .replace('"__DECRYPT_CLIENT_REQUESTS__"', str(decrypt_client_requests))
        .replace('"__ENCRYPT_CLIENT_RESPONSES__"', str(encrypt_client_responses))
        .replace('"__LOG_TO_FILE__"', str(log_to_file))
        .replace('"__LOG_FILE_PATH__"', f'"{log_file_path}"')
        .replace('"__REGEX_EXTRACT_PATTERN__"', f'"{regex_pattern}"')
        .replace('"__REGEX_EXTRACT_FILE__"', f'"{regex_output_file}"')
        .replace('"__RATE_LIMIT_QPS__"', str(rate_limit_qps))
    )

    # -----------------------------
    # Proxy2 generation (server-side)
    # -----------------------------
    proxy2_code = (
        script2_template
        .replace("__TARGET_DOMAIN__", target_domain)
        .replace("__ALGORITHM__", algorithm)
        .replace("__KEY__", repr(key_literal))
        .replace("__CREDENTIAL_FORMAT__", credential_format)
        .replace('"__ENCRYPT_TO_SERVER__"', str(encrypt_to_server))
        .replace('"__DECRYPT_FROM_SERVER__"', str(decrypt_from_server))
        .replace('"__ALLOWED_METHODS__"', allowed_methods_py)
        .replace('"__LOG_TO_FILE__"', str(log_to_file))
        .replace('"__LOG_FILE_PATH__"', f'"{log_file_path}"')
        .replace('"__REGEX_EXTRACT_PATTERN__"', f'"{regex_pattern}"')
        .replace('"__REGEX_EXTRACT_FILE__"', f'"{regex_output_file}"')
        .replace('"__RATE_LIMIT_QPS__"', str(rate_limit_qps))
        # -----------------------------
        # NEW: Targeting & Filtering placeholders
        # -----------------------------
        .replace('"__FILTER_BY_DOMAIN__"', str(filter_by_domain))
        .replace('"__FILTER_DOMAIN_PATTERN__"', f'"{filter_domain_pattern}"')
        .replace('"__FILTER_BY_URL_PATH__"', str(filter_by_url_path))
        .replace('"__FILTER_URL_PATH_PATTERN__"', f'"{filter_url_path_pattern}"')
        .replace('"__FILTER_BY_HTTP_METHOD__"', str(filter_by_http_method))
        .replace('"__FILTER_BY_REQUEST_HEADER__"', str(filter_by_request_header))
        .replace('"__FILTER_REQUEST_HEADER_NAME__"', f'"{filter_request_header_name}"')
        .replace('"__FILTER_REQUEST_HEADER_VALUE__"', f'"{filter_request_header_value}"')
        .replace('"__FILTER_BY_RESPONSE_HEADER__"', str(filter_by_response_header))
        .replace('"__FILTER_RESPONSE_HEADER_NAME__"', f'"{filter_response_header_name}"')
        .replace('"__FILTER_RESPONSE_HEADER_VALUE__"', f'"{filter_response_header_value}"')
        .replace('"__FILTER_BY_BODY_CONTENT__"', str(filter_by_body_content))
        .replace('"__FILTER_BODY_CONTENT_PATTERN__"', f'"{filter_body_content_pattern}"')
        .replace('"__FILTER_BY_CLIENT_IP__"', str(filter_by_client_ip))
        .replace('"__FILTER_CLIENT_IP_ADDRESS__"', f'"{filter_client_ip_address}"')
        # NEW: Advanced request mods (UA/Host/method/redirect/rewrite)
        .replace('"__MODIFY_USER_AGENT_ENABLED__"', str(modify_user_agent_enabled))
        .replace('"__CUSTOM_USER_AGENT__"', f'"{custom_user_agent}"')
        .replace('"__MODIFY_HOST_HEADER_ENABLED__"', str(modify_host_header_enabled))
        .replace('"__CUSTOM_HOST_HEADER__"', f'"{custom_host_header}"')
        .replace('"__CHANGE_REQUEST_METHOD_ENABLED__"', str(change_request_method_enabled))
        .replace('"__REQUEST_METHOD_FROM__"', f'"{request_method_from}"')
        .replace('"__REQUEST_METHOD_TO__"', f'"{request_method_to}"')
        .replace('"__REDIRECT_REQUEST_ENABLED__"', str(redirect_request_enabled))
        .replace('"__REDIRECT_TO_HOST__"', f'"{redirect_to_host}"')
        .replace('"__REDIRECT_TO_PORT__"', str(redirect_to_port_int))
        .replace('"__REWRITE_URL_ENABLED__"', str(rewrite_url_enabled))
        .replace('"__URL_REWRITE_PATTERN__"', f'"{url_rewrite_pattern}"')
        .replace('"__URL_REWRITE_WITH__"', f'"{url_rewrite_with}"')
        # block regex
        .replace('"__BLOCK_ENABLED__"', str(block_enabled))
        .replace('"__BLOCK_PATTERN__"', f'"{block_pattern}"')
        # request header/body mods
        .replace('"__ADD_REQ_HEADERS_ENABLED__"', str(add_req_headers_enabled))
        .replace("__REQ_HEADERS_TO_ADD__", repr(req_headers_to_add))
        .replace('"__REMOVE_REQ_HEADERS_ENABLED__"', str(remove_req_headers_enabled))
        .replace("__REQ_HEADERS_TO_REMOVE__", repr(req_headers_to_remove))
        .replace('"__REPLACE_REQUEST_BODY_ENABLED__"', str(replace_req_body_enabled))
        .replace('"__REQ_BODY_REPLACE_PATTERN__"', f'"{req_body_replace_pattern}"')
        .replace('"__REQ_BODY_REPLACE_WITH__"', f'"{req_body_replace_with}"')
        # response header/body mods + HTML/JS
        .replace('"__ADD_RESP_HEADERS_ENABLED__"', str(add_resp_headers_enabled))
        .replace("__RESP_HEADERS_TO_ADD__", repr(resp_headers_to_add))
        .replace('"__REMOVE_RESP_HEADERS_ENABLED__"', str(remove_resp_headers_enabled))
        .replace("__RESP_HEADERS_TO_REMOVE__", repr(resp_headers_to_remove))
        .replace('"__REPLACE_RESPONSE_BODY_ENABLED__"', str(replace_resp_body_enabled))
        .replace('"__RESP_BODY_REPLACE_PATTERN__"', f'"{resp_body_replace_pattern}"')
        .replace('"__RESP_BODY_REPLACE_WITH__"', f'"{resp_body_replace_with}"')
        .replace('"__INJECT_HTML_JS_ENABLED__"', str(inject_html_js_enabled))
        .replace("__HTML_JS_INJECTION_CODE__", repr(html_js_injection_code))
        .replace('"__INJECT_HTML_JS_ENABLED__"', str(inject_html_js_enabled))
        .replace("__HTML_JS_INJECTION_CODE__", repr(html_js_injection_code))
        # NEW: cookies
        .replace('"__MODIFY_COOKIES_ENABLED__"', str(modify_cookies_enabled))
        .replace("__COOKIE_MODIFICATIONS__", repr(cookie_modifications))
        # NEW: change status code (mapping)
        .replace('"__CHANGE_STATUS_CODE_ENABLED__"', str(change_status_code_enabled))
        .replace('"__STATUS_CODE_FROM__"', str(status_code_from))
        .replace('"__STATUS_CODE_TO__"', str(status_code_to))
                # -------- Advanced & Utility Features --------
        .replace('"__AUTO_HANDLE_AUTH_ENABLED__"', str(auto_handle_auth))
        .replace('"__AUTH_TOKEN__"', f'"{auth_token}"')
        .replace('"__REPLAY_ATTACK_ENABLED__"', str(replay_attack_enabled))
        .replace('"__REPLAY_COUNT__"', str(replay_count))
        .replace('"__ENABLE_AUTO_SCAN__"', str(enable_auto_scan))
        .replace("__CUSTOM_HEADERS_GLOBAL__", repr(custom_headers_global))
        .replace('"__CUSTOM_DECRYPT_FUNCTION_ENABLED__"', str(custom_decrypt_function_enabled))
        .replace("__DECRYPT_FUNCTION_CODE__", repr(decrypt_function_code))
        .replace('"__CUSTOM_ENCRYPT_FUNCTION_ENABLED__"', str(custom_encrypt_function_enabled))
        .replace("__ENCRYPT_FUNCTION_CODE__", repr(encrypt_function_code))

    )




    return jsonify({
        "proxy1": proxy1_code,
        "proxy2": proxy2_code,
        "util": util_code,
    })


if __name__ == "__main__":
    # Match your frontend's API_URL
    app.run(host="127.0.0.1", port=5001, debug=True)
