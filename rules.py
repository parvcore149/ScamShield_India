"""Deterministic checks: message signals and structural URL analysis (no network access)."""
import ipaddress
import re
from urllib.parse import urlparse

# category -> (description, patterns). English, Hinglish and Hindi.
SIGNALS = {
    "credential_request": ("Asks for OTP, PIN, password, CVV or card details", [
        r"\b(otp|pin|cvv|password|passcode)\b.{0,40}\b(share|send|tell|enter|provide|bata)",
        r"\b(share|send|tell|enter|provide)\b.{0,40}\b(otp|pin|cvv|password)\b",
        r"\botp\s+(bata|batao|bhejo|share)", r"ओटीपी", r"\bcard number\b"]),
    "urgency_threat": ("Urgent or threatening language", [
        r"\b(urgent|immediately|within \d+ (hours?|minutes?)|last chance|final notice|act now)\b",
        r"\b(account|sim|card)\b.{0,30}\b(blocked|suspended|closed|deactivated)\b",
        r"\b(turant|jaldi)\b", r"खाता.{0,10}(बंद|ब्लॉक)", r"तुरंत"]),
    "prize_reward": ("Prize, lottery or reward claim", [
        r"\b(you (have )?won|lottery|lucky draw|claim (your )?(prize|reward|gift))\b",
        r"\binaam\b", r"इनाम"]),
    "job_offer": ("Suspicious job or task offer", [
        r"\b(work from home|earn \S+ (per|a) (day|hour)|registration fee|like and (earn|subscribe))\b"]),
    "money_transfer": ("Asks you to pay or transfer money", [
        r"\b(pay|send|transfer|deposit)\b.{0,30}(₹|rs\.?|inr|\b\d{3,})",
        r"\b(upi|collect request)\b.{0,30}\b(approve|accept|pin)\b", r"\bprocessing fee\b"]),
    "delivery_payment": ("Delivery or customs fee request", [
        r"\b(package|parcel|delivery|courier)\b.{0,60}\b(fee|pay|address|failed|held|pending)\b"]),
    "impersonation": ("Claims to be a bank, government body or known brand", [
        r"\b(sbi|hdfc|icici|axis|paytm|phonepe|rbi|income tax|kyc|trai|customs|amazon|flipkart)\b"]),
}
STRONG = {"credential_request"}  # alone, enough for High

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy", "shorturl.at", "tiny.cc"}
BRANDS = ["sbi", "hdfc", "icici", "axis", "paytm", "phonepe", "amazon", "flipkart", "google", "irctc", "npci"]
RISKY_TLDS = {"xyz", "top", "click", "icu", "work", "rest", "support", "buzz", "tk", "cf", "gq"}
URL_RE = re.compile(r"https?://[^\s<>\"']+|www\.[^\s<>\"']+", re.I)


def find_signals(text: str) -> list[dict]:
    """One finding per matched category, with the exact matched snippet as evidence."""
    findings = []
    for cat, (desc, patterns) in SIGNALS.items():
        for p in patterns:
            m = re.search(p, text, re.I | re.S)
            if m:
                findings.append({"category": cat, "description": desc, "evidence": m.group(0)[:120]})
                break
    return findings


def analyze_url(raw: str) -> dict:
    """Structural analysis only. Never fetches the URL."""
    raw = raw.strip()
    url = raw if re.match(r"^[a-z][a-z0-9+.-]*://", raw, re.I) else "http://" + raw
    flags: list[str] = []
    try:
        p = urlparse(url)
        host = (p.hostname or "").lower()
        port = p.port
    except ValueError:
        return {"url": raw, "valid": False, "flags": ["Not a valid URL"]}
    if p.scheme not in ("http", "https") or not host or " " in raw:
        return {"url": raw, "valid": False, "flags": ["Not a valid web URL"]}
    if p.scheme == "http":
        flags.append("Uses unencrypted http")
    if port not in (None, 80, 443):
        flags.append(f"Unusual port {port}")
    if "@" in p.netloc:
        flags.append("Contains '@' which can hide the real destination")
    try:
        ipaddress.ip_address(host)
        flags.append("Host is a raw IP address")
    except ValueError:
        labels = host.split(".")
        if host in SHORTENERS:
            flags.append("URL shortener hides the final destination")
        if len(labels) > 4:
            flags.append("Unusually many subdomains")
        if any(l.startswith("xn--") for l in labels):
            flags.append("Punycode hostname (possible lookalike characters)")
        if labels[-1] in RISKY_TLDS:
            flags.append(f"Top-level domain .{labels[-1]} is often abused (not proof of fraud)")
        n = 3 if len(labels) >= 3 and labels[-2] in {"co", "gov", "nic", "org", "ac", "net"} else 2
        registered = ".".join(labels[-n:])
        for b in BRANDS:
            if b in host and registered.split(".")[0] != b:
                flags.append(f"Mentions '{b}' but the real domain is {registered}")
                break
        if host.count("-") >= 3:
            flags.append("Many hyphens in hostname")
    return {"url": raw, "valid": True, "host": host, "flags": flags}


def rule_risk(signals: list[dict], url_results: list[dict]) -> tuple[str, str]:
    """Documented heuristic (not a probability):
    High   = credential/OTP request, OR 3+ signal categories, OR 2+ categories plus a flagged URL.
    Medium = 2 categories, OR 1 category plus a flagged URL, OR a URL with 2+ flags.
    Low    = otherwise (one keyword alone is not treated as evidence of fraud)."""
    cats = {s["category"] for s in signals}
    valid = [u for u in url_results if u.get("valid")]
    bad_url = any(u["flags"] for u in valid)
    many_flags = any(len(u["flags"]) >= 2 for u in valid)
    if cats & STRONG or len(cats) >= 3 or (len(cats) >= 2 and bad_url):
        return "High", "credential request, 3+ signal types, or 2+ signals with a flagged URL"
    if len(cats) == 2 or (cats and bad_url) or many_flags:
        return "Medium", "2 signal types, 1 signal with a flagged URL, or a URL with 2+ flags"
    return "Low", "signals did not meet the Medium threshold"
