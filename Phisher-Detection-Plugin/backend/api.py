# api.py — localhost-only service with majority vote and per-request logging
#
# This service exposes a simple HTTP API (Flask) to classify URLs as
# Phishing / Legitimate / Suspicious using:
#   - A local ML model (stacking ensemble)
#   - Google Safe Browsing 
#   - VirusTotal URL report 
# The final verdict is a majority vote (2-out-of-3).

import os, re, ipaddress, configparser
from urllib.parse import urlparse
from datetime import datetime, timezone

import joblib, requests, numpy as np, pandas as pd
from flask import Flask, request, jsonify, make_response

# eTLD+1 extraction (helps with multi-suffix domains like google.co.in)
# Try to use tldextract (best option). If it's not available, fall back to a
# simple manual multi-suffix list below.
try:
    import tldextract
    _tldextract = tldextract.TLDExtract(suffix_list_urls=None)  # offline suffix list
except Exception:
    _tldextract = None

def etld1(host: str) -> str:
    """Return eTLD+1 (registered domain) for a host, e.g. 'sub.example.co.uk' -> 'example.co.uk'."""
    host = (host or "").lower().strip()
    if not host:
        return ""
    # Preferred path: use tldextract if available.
    if _tldextract:
        ext = _tldextract(host)
        return ext.registered_domain or host

    # Fallback: hand-maintained list of common multi-label suffixes.
    ml = ("co.uk","ac.uk","gov.uk","co.in","com.au","com.br","com.mx","co.jp","co.kr","co.za","com.sg","com.hk")
    parts = host.split(".")
    if len(parts) < 2:
        return host
    suf2 = ".".join(parts[-2:])
    if any(suf2.endswith(t) for t in ml) and len(parts) >= 3:
        return ".".join(parts[-3:])
    return suf2

# -----------------------------------------------------------------------------
# config
# -----------------------------------------------------------------------------

CONFIG_PATH = os.getenv("APP_CONFIG_PATH", "config.ini")
config = configparser.ConfigParser()
if os.path.exists(CONFIG_PATH):
    config.read(CONFIG_PATH)

# API keys can come from environment variables or config.ini.
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY") or config.get("API_KEYS","GOOGLE_API_KEY", fallback=None)
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY") or config.get("API_KEYS","VIRUSTOTAL_API_KEY", fallback=None)

# Paths to model artifacts (can be overridden with env vars).
MODEL_PATH    = os.getenv("MODEL_PATH", "phishing_stacking_model.pkl")
SCALER_PATH   = os.getenv("SCALER_PATH", "scaler.pkl")
FEATURES_PATH = os.getenv("FEATURES_PATH", "feature_names.pkl")

# -----------------------------------------------------------------------------
# load artifacts
# -----------------------------------------------------------------------------
# Load the stacking model and scaler; also figure out which feature names
# the scaler / model expect.
model = joblib.load(MODEL_PATH)
scaler = joblib.load(SCALER_PATH)
required_features = list(getattr(scaler, "feature_names_in_", []))
if not required_features:
    # Fallback: if scaler doesn't carry feature names (older artifact), load them separately.
    required_features = list(joblib.load(FEATURES_PATH))

print(f"[BOOT] Serving with {len(required_features)} features. First 8: {required_features[:8]}")

# -----------------------------------------------------------------------------
# Flask app (localhost-only + CORS)
# -----------------------------------------------------------------------------
app = Flask(__name__)

# Allow only local/private networks to hit this API.
LOCAL_NETS = [
    ipaddress.ip_network("127.0.0.0/8"),   # IPv4 loopback
    ipaddress.ip_network("::1/128"),       # IPv6 loopback
    ipaddress.ip_network("10.0.0.0/8"),    # RFC1918 private ranges
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
]
def _is_local(addr: str):
    """Return True if addr is from a local/allowed network."""
    try:
        return any(ipaddress.ip_address(addr) in net for net in LOCAL_NETS)
    except Exception:
        # On any parsing error, treat as non-local (safer).
        return False

@app.before_request
def _localhost_gate_and_log():
    """Reject non-local requests and log all calls with timestamps."""
    client = request.remote_addr or ""
    if not _is_local(client):
        return jsonify({"error":"Forbidden (localhost only)"}), 403
    print(f"[{datetime.now(timezone.utc).isoformat()}] {request.method} {request.path} from {client}")

@app.after_request
def _cors(resp):
    """
    Add permissive CORS headers.
    If the request comes from a Chrome extension, echo back that origin,
    otherwise fall back to '*'.
    """
    origin = request.headers.get("Origin")
    allow = origin if origin and origin.startswith("chrome-extension://") else "*"
    resp.headers["Access-Control-Allow-Origin"] = allow
    resp.headers["Vary"] = "Origin"
    resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    return resp

@app.route("/health", methods=["GET","OPTIONS"])
def health():
    """Lightweight health endpoint for readiness checks."""
    if request.method == "OPTIONS": return make_response("", 204)
    return jsonify({"status":"ok"}), 200

# Generic OPTIONS handler for any other path.
@app.route("/<path:any>", methods=["OPTIONS"])
def any_options(any): return make_response("", 204)

# -----------------------------------------------------------------------------
# feature engineering (URL + light HTML signals)
# -----------------------------------------------------------------------------

# Matches http:// or https:// for stripping schemes.
_URL_RE = re.compile(r"https?://", re.IGNORECASE)

def _count_regex(s, pat):
    """Count non-overlapping occurrences of a regex pattern in a string."""
    return len(re.findall(pat, s))

def _is_ip(h):
    """Return True if host-like value is a literal IP address."""
    try:
        ipaddress.ip_address(h)
        return True
    except Exception:
        return False

def _subdomain_level(host: str) -> int:
    """
    Estimate subdomain depth relative to the registered domain.
    Example:
        'a.b.example.com' -> 2
        'example.com' -> 0
    """
    parts = [p for p in host.split(".") if p]
    base = etld1(host)
    if not base or base == host:
        return max(len(parts) - 2, 0)
    if host.endswith(base):
        head = host[: -len(base)].rstrip(".")
        return len([p for p in head.split(".") if p])
    return max(len(parts) - 2, 0)

def compute_features(url: str) -> dict:
    """
    Compute all URL / content-based features for a single URL.

    This includes:
      - lexical URL stats (length, symbols, digits, etc.)
      - subdomain / path structure
      - lightweight HTML scraping (forms, links, iframes, etc.)
    """
    parsed = urlparse(url)
    host = (parsed.netloc or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""
    url_lc = url.lower()
    # URL without scheme (e.g., remove 'https://') for dot counting.
    url_ns = _URL_RE.sub("", url)

    base_reg = etld1(host)
    reg_label = base_reg.split(".")[0] if base_reg else ""

    feats = {}

    # ----------------- Lexical / structural features -----------------
    feats["NumDots"] = url_ns.count(".")
    feats["SubdomainLevel"] = _subdomain_level(host)
    feats["PathLevel"] = max(len([p for p in path.split("/") if p]), 0)
    feats["UrlLength"] = len(url)
    feats["NumDash"] = url.count("-")
    feats["NumDashInHostname"] = host.count("-")
    feats["NumUnderscore"] = url.count("_")
    feats["NumQueryComponents"] = len([p for p in query.split("&") if p]) if query else 0
    feats["NumAmpersand"] = url.count("&")
    feats["NumHash"] = url.count("#")
    feats["NumNumericChars"] = _count_regex(url, r"\d")
    feats["NoHttps"] = 0 if url_lc.startswith("https://") else 1
    feats["IpAddress"] = 1 if _is_ip(host) else 0
    feats["HostnameLength"] = len(host)
    feats["PathLength"] = len(path)
    feats["QueryLength"] = len(query)
    feats["AtSymbol"] = 1 if "@" in url else 0
    feats["TildeSymbol"] = 1 if "~" in url else 0
    feats["DoubleSlashInPath"] = 1 if "//" in path else 0
    # Simple risk flag for very long URLs
    feats["UrlLengthRT"] = 1.0 if feats["UrlLength"] > 75 else 0.0

    # Domain mentions (based on eTLD+1)
    feats["DomainInPaths"] = 1 if reg_label and reg_label in path.lower() else 0
    # Portion of hostname before the registered domain (subdomain bit)
    sub_only = host[: -len(base_reg)].rstrip(".") if base_reg and host.endswith(base_reg) else host
    feats["DomainInSubdomains"] = 1 if reg_label and reg_label in sub_only else 0

    # ----------------- Lightweight content fetch -----------------
    # Note: a short timeout is used so we don't hang forever when URLs are slow.
    try:
        r = requests.get(url, headers={"User-Agent":"Mozilla/5.0"}, timeout=5, allow_redirects=True)
        final_url = r.url
        # Only keep HTML content; ignore e.g. PDFs or binaries.
        html = r.text if "text/html" in r.headers.get("Content-Type","") else ""
    except Exception:
        final_url, html = url, ""

    # One-bit redirect indicator (any redirect at all).
    feats["RedirectCount"] = 1 if final_url != url else 0

    # ----------------- HTML parsing (very coarse, regex-based) -----------------
    hrefs = re.findall(r'href\s*=\s*["\']([^"\']+)["\']', html, flags=re.I)
    srcs  = re.findall(r'src\s*=\s*["\']([^"\']+)["\']',  html, flags=re.I)
    forms = re.findall(r"<form\b[^>]*>(.*?)</form>", html, flags=re.I|re.S)
    actions = re.findall(r'<form[^>]*action\s*=\s*["\']([^"\']*)["\']', html, flags=re.I)
    favicons = re.findall(r'<link[^>]*rel=["\'](?:shortcut )?icon["\'][^>]*href=["\']([^"\']+)["\']', html, flags=re.I)
    iframes = re.findall(r"<iframe\b[^>]*>", html, flags=re.I)
    frames  = re.findall(r"<frame\b[^>]*>",  html, flags=re.I)

    def _norm(u: str) -> str:
        """Normalize a URL-ish string, expanding protocol-relative URLs."""
        u = (u or "").strip()
        # Handle URLs like //example.com/favicon.ico
        return ("http:" + u) if u.startswith("//") else u

    def _is_external(u: str) -> bool:
        """Check whether a URL points to a different registered domain."""
        u = _norm(u).lower()
        if not (u.startswith("http://") or u.startswith("https://")):
            return False
        try:
            dom = etld1(urlparse(u).netloc.lower())
            return dom and dom != base_reg
        except Exception:
            return False

    # ----------------- Link features -----------------
    total_links = len(hrefs)
    ext_links = sum(1 for h in hrefs if _is_external(h))
    # "Null/self" links like '#', 'javascript:void(0)', etc.
    null_self = sum(1 for h in hrefs if (h or "").strip().lower() in ("", "#", "javascript:void(0)", "about:blank"))
    feats["PctExtHyperlinks"] = 0.0 if total_links == 0 else 100.0 * ext_links / total_links
    feats["PctNullSelfRedirectHyperlinks"] = 0.0 if total_links == 0 else 100.0 * null_self / total_links
    # Binary risk flag if more than half the links are null/self redirects.
    feats["PctExtNullSelfRedirectHyperlinksRT"] = 1.0 if feats["PctNullSelfRedirectHyperlinks"] > 50.0 else 0.0

    # ----------------- Resource (src) features -----------------
    total_src = len(srcs)
    ext_src = sum(1 for s in srcs if _is_external(s))
    feats["PctExtResourceUrls"] = 0.0 if total_src == 0 else 100.0 * ext_src / total_src
    # Another risk flag when external resource usage is high.
    feats["PctExtResourceUrlsRT"] = 1.0 if feats["PctExtResourceUrls"] > 50.0 else 0.0

    # ----------------- Form-related features -----------------
    insecure = abnormal = img_only = submit_email = 0
    if forms:
        for i, f in enumerate(forms):
            a = (actions[i] if i < len(actions) else "").strip().lower()
            # Insecure forms: page is HTTPS but form posts to HTTP or has empty action.
            if url_lc.startswith("https://"):
                if a == "" or a.startswith("http://"): insecure += 1
            # Abnormal form action: posts to a different domain entirely.
            if a.startswith("http://") or a.startswith("https://"):
                try:
                    adom = etld1(urlparse(a).netloc.lower())
                    if adom and adom != base_reg: abnormal += 1
                except Exception:
                    pass
            # Forms that only contain an <img>, often used as visual baits.
            if re.search(r"<input\b", f, flags=re.I) is None and re.search(r"<img\b", f, flags=re.I):
                img_only += 1
            # Information submitted directly via mailto.
            if a.startswith("mailto:") or re.search(r"mailto:", f, flags=re.I):
                submit_email += 1

    feats["InsecureForms"] = 1 if insecure > 0 else 0
    feats["AbnormalFormAction"] = 1 if abnormal > 0 else 0
    feats["AbnormalExtFormActionR"] = 1.0 if abnormal > 0 else 0.0
    feats["ImagesOnlyInForm"] = 1 if img_only > 0 else 0
    feats["SubmitInfoToEmail"] = 1 if submit_email > 0 else 0

    # ----------------- Frames and favicon -----------------
    feats["IframeOrFrame"] = 1 if (iframes or frames) else 0
    feats["Favicon"] = 1 if favicons else 0
    feats["ExtFavicon"] = 0
    for fv in favicons:
        try:
            dom = etld1(urlparse(_norm(fv)).netloc.lower())
            if dom and dom != base_reg:
                feats["ExtFavicon"] = 1
                break
        except Exception:
            # Ignore parsing errors and keep ExtFavicon as-is.
            pass

    # ----------------- Domain mismatch (external dominance) -----------------
    tot_all = total_links + total_src
    feats["FrequentDomainNameMismatch"] = 1 if (tot_all > 0 and float(ext_links + ext_src) / tot_all > 0.5) else 0

    return feats

def build_frame(url: str) -> pd.DataFrame:
    """
    Build a single-row DataFrame with all required features, ordered exactly as
    expected by the scaler / model.
    """
    feats = compute_features(url)
    # Ensure every required feature is present; missing features default to 0.0.
    row = {name: float(feats.get(name, 0.0)) for name in required_features}
    return pd.DataFrame([row], columns=required_features)

# -----------------------------------------------------------------------------
# external reputation 
# -----------------------------------------------------------------------------

def check_gsb(u: str) -> str:
    """
    Query Google Safe Browsing for URL reputation.
    Returns: "Phishing", "Legitimate", or "Unknown" (on error / no key).
    """
    if not GOOGLE_API_KEY: return "Unknown"
    api = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_API_KEY}"
    payload = {
        "client":{"clientId":"phish-detector","clientVersion":"1.0"},
        "threatInfo":{
            "threatTypes":["MALWARE","SOCIAL_ENGINEERING","UNWANTED_SOFTWARE","POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes":["ANY_PLATFORM"],
            "threatEntryTypes":["URL"],
            "threatEntries":[{"url":u}]
        }
    }
    try:
        r = requests.post(api, json=payload, timeout=6)
        if r.status_code == 200:
            # If any matches are returned, treat it as phishing.
            return "Phishing" if r.json().get("matches") else "Legitimate"
        return "Unknown"
    except requests.RequestException:
        # Network issues or timeouts just degrade to "Unknown", model still works.
        return "Unknown"

def check_vt(u: str) -> str:
    """
    Query VirusTotal URL report.
    Returns: "Phishing", "Legitimate", or "Unknown" on error / no key.
    """
    if not VIRUSTOTAL_API_KEY: return "Unknown"
    api = "https://www.virustotal.com/vtapi/v2/url/report"
    try:
        r = requests.get(api, params={"apikey":VIRUSTOTAL_API_KEY,"resource":u,"allinfo":"false"}, timeout=6)
        if r.status_code != 200: return "Unknown"
        data = r.json()
        if data.get("response_code") == 1:
            # If any engine flags it as malicious, call it "Phishing".
            return "Phishing" if (data.get("positives",0) or 0) > 0 else "Legitimate"
        return "Unknown"
    except requests.RequestException:
        return "Unknown"

# -----------------------------------------------------------------------------
# majority vote (2-of-3)
# -----------------------------------------------------------------------------

def fuse_verdict(model_label: str, gsb: str, vt: str) -> str:
    """
    Combine the three labels via simple majority voting:
      - If at least two say "Phishing"    -> Phishing
      - If at least two say "Legitimate"  -> Legitimate
      - Otherwise                         -> Suspicious
    """
    labels = [model_label, gsb, vt]
    phish = sum(1 for v in labels if v == "Phishing")
    legit = sum(1 for v in labels if v == "Legitimate")
    if phish >= 2: return "Phishing"
    if legit >= 2: return "Legitimate"
    return "Suspicious"

# -----------------------------------------------------------------------------
# request parsing (accepts query, JSON, form, or raw body)
# -----------------------------------------------------------------------------

def get_url_from_request():
    """
    Extract a URL from the incoming request.

    Accepted locations / keys:
      - Query params: ?url=, ?link=, ?target=, ?page=, ?u=
      - JSON body: same keys as above
      - Form data: same keys as above
      - Raw text body: must be a bare http:// or https:// URL
    """
    # 1) Query string
    for k in ("url","link","target","page","u"):
        v = request.args.get(k)
        if v: return v.strip()

    # 2) JSON body
    js = request.get_json(silent=True)
    if isinstance(js, dict):
        for k in ("url","link","target","page","u"):
            v = js.get(k)
            if isinstance(v,str) and v.strip(): return v.strip()

    # 3) Form-encoded body
    if request.form:
        for k in ("url","link","target","page","u"):
            v = request.form.get(k)
            if v: return v.strip()

    # 4) Raw text body
    raw = (request.get_data(as_text=True) or "").strip()
    if raw.startswith("http://") or raw.startswith("https://"): return raw

    return None

# -----------------------------------------------------------------------------
# core handler
# -----------------------------------------------------------------------------

def analyze_core():
    """
    Core analysis pipeline:
      - parse URL from request
      - compute features + scale
      - run model prediction
      - call GSB / VirusTotal (if enabled)
      - fuse via majority vote and return a JSON verdict
    """
    u = get_url_from_request()
    if not u:
        return jsonify({"error":"No URL provided. Use ?url=… or JSON/form/text."}), 400

    # Build feature frame, scale it, and run the classifier.
    X = build_frame(u)
    Xs = scaler.transform(X)
    pred = model.predict(Xs)[0]
    model_label = "Phishing" if bool(pred) else "Legitimate"

    # External reputation checks (may return "Unknown").
    gsb = check_gsb(u)
    vt  = check_vt(u)
    final = fuse_verdict(model_label, gsb, vt)

    print(f"[PRED] url={u}  model={model_label}  gsb={gsb}  vt={vt}  final={final}")

    # JSON response keeps a couple of redundant fields for convenience.
    return jsonify({
        "final_verdict": final,
        "details": {
            "Phisher Model": model_label,
            "Google Safe Browsing": gsb,
            "VirusTotal": vt
        },
        "status": final,
        "verdict": final,
        "is_phishing": (final == "Phishing")
    }), 200

# Expose the same behavior on three different endpoints for convenience.
@app.route("/analyze", methods=["GET","POST","OPTIONS"])
def analyze():
    if request.method == "OPTIONS": return make_response("", 204)
    return analyze_core()

@app.route("/scan", methods=["GET","POST","OPTIONS"])
def scan():
    if request.method == "OPTIONS": return make_response("", 204)
    return analyze_core()

@app.route("/check", methods=["GET","POST","OPTIONS"])
def check():
    if request.method == "OPTIONS": return make_response("", 204)
    return analyze_core()

# -----------------------------------------------------------------------------
# entrypoint
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    # Bind to 127.0.0.1 to enforce localhost-only; port is configurable via $PORT.
    app.run(host="127.0.0.1", port=int(os.getenv("PORT","5000")), debug=False)
