"""Validate -> rules -> local AI -> merge. Message text is never logged or stored."""
import re
import unicodedata

from . import llm, rules

MAX_CHARS = 4000
ORDER = {"Low": 0, "Medium": 1, "High": 2}
ACTIONS = ["Do not click links or share OTP, PIN, CVV or passwords.",
           "Contact the organisation using the number on its official website or card.",
           "Report cyber fraud at cybercrime.gov.in or call 1930 (India)."]


def normalize(text: str) -> str:
    text = unicodedata.normalize("NFKC", text or "")
    text = "".join(c for c in text if c.isprintable() or c in "\n\t")
    return re.sub(r"[ \t]+", " ", text).strip()


def analyze(message: str = "", url: str = "", use_ai: bool = True, ai_fn=None) -> dict:
    ai_fn = ai_fn or llm.ask_model
    message, url = normalize(message), normalize(url)
    if not message and not url:
        raise ValueError("Please paste a message or enter a URL.")
    if len(message) > MAX_CHARS or len(url) > 2048:
        raise ValueError(f"Input too long (max {MAX_CHARS} characters for messages).")
    urls = [u.rstrip(".,)") for u in rules.URL_RE.findall(message)] + ([url] if url else [])
    url_results = [rules.analyze_url(u) for u in dict.fromkeys(urls)][:5]
    signals = rules.find_signals(message)
    rule_level, basis = rules.rule_risk(signals, url_results)

    ai, status = None, "skipped"
    if use_ai and message:
        try:
            ai, status = ai_fn(message, urls), "ok"
        except llm.AIUnavailable as e:
            status = f"unavailable ({e})"
    level = rule_level
    if ai and ORDER[ai["risk_level"]] > ORDER[level]:
        level = ai["risk_level"]  # AI may raise concern but never lowers the rule-based level.
    limits = ["This is an aid, not proof that a message is safe or fraudulent.",
              "URL checks are structural only; no live threat-intelligence lookup was done.",
              "The risk level is a documented heuristic, not a validated probability."]
    if not ai and use_ai and message:
        limits.append("The local AI model was unavailable, so only rule-based checks were used.")
    return {"risk_level": level, "mode": "ai+rules" if ai else "rules-only fallback",
            "rules": {"level": rule_level, "basis": basis, "signals": signals, "urls": url_results},
            "ai": {"status": status, "model": llm.MODEL, "result": ai},
            "recommended_actions": (ai["recommended_actions"] if ai else []) + ACTIONS,
            "limitations": limits}
