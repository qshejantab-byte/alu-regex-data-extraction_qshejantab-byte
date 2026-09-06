"""
Regex Onboarding Hackathon - Data Extraction & Secure Validation
Author: Quentin

Reads raw text (e.g. from an external API response), pulls out structured
data with regex, validates it, and refuses to treat hostile-looking input
as real data. Sensitive fields are masked before they ever get printed,
logged, or written to the output file.
"""

import json
import re
from pathlib import Path

INPUT_FILE = Path(__file__).resolve().parent.parent / "input" / "raw-text.txt"
OUTPUT_FILE = Path(__file__).resolve().parent.parent / "output" / "sample-output.json"


# ---------------------------------------------------------------------------
# 1. Security: filter out hostile / malformed lines before we extract anything
# ---------------------------------------------------------------------------
# The API response is untrusted input. Some lines in a real feed could try to
# inject script tags, SQL, path traversal, or prompt-injection style text
# ("ignore previous instructions ..."). We never execute or forward that
# text - we just drop the whole line from processing and count it, so the
# rest of the pipeline never sees it.
SUSPICIOUS_PATTERNS = [
    re.compile(r"<\s*script", re.IGNORECASE),          # script injection
    re.compile(r"\bDROP\s+TABLE\b", re.IGNORECASE),      # SQL injection
    re.compile(r"'\s*OR\s*'1'\s*=\s*'1", re.IGNORECASE),  # classic SQLi
    re.compile(r"\.\./\.\./"),                           # path traversal
    re.compile(r"ignore\s+all\s+previous\s+instructions", re.IGNORECASE),
    re.compile(r"\bfetch\s*\(", re.IGNORECASE),          # exfil-style JS call
]


def strip_hostile_lines(raw_text):
    """Return (clean_text, number_of_blocked_lines). Never prints the
    blocked content itself - only a count - so we don't re-expose it."""
    clean_lines = []
    blocked = 0
    for line in raw_text.splitlines():
        if any(p.search(line) for p in SUSPICIOUS_PATTERNS):
            blocked += 1
            continue
        clean_lines.append(line)
    return "\n".join(clean_lines), blocked


# ---------------------------------------------------------------------------
# 2. Regex patterns
# ---------------------------------------------------------------------------

# General email: local part + @ + domain. Deliberately doesn't accept
# doubled dots or a bare "@@" - that's what trips up things like
# "not-an-email@@doubled..dots" in the sample input.
EMAIL_PATTERN = re.compile(
    r"\b[A-Za-z0-9](?:[A-Za-z0-9._%+-]*[A-Za-z0-9])?"
    r"@[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+\b"
)

# ALU-specific domains, checked against whatever EMAIL_PATTERN already found.
ALU_DOMAIN_RULES = {
    "official": re.compile(r"@alueducation\.com$", re.IGNORECASE),
    "alumni": re.compile(r"@alumni\.alueducation\.com$", re.IGNORECASE),
    "si": re.compile(r"@si\.alueducation\.com$", re.IGNORECASE),
}

# Card networks by leading digits, with optional spaces or dashes every 4
# digits. Grouped so Amex's 4-6-5 layout still matches.
CREDIT_CARD_PATTERN = re.compile(
    r"\b(?:"
    r"4\d{3}(?:[ -]?\d{4}){3}"                       # Visa - 16 digits
    r"|5[1-5]\d{2}(?:[ -]?\d{4}){3}"                  # Mastercard - 16 digits
    r"|6011(?:[ -]?\d{4}){3}"                         # Discover
    r"|3[47]\d{2}[ -]?\d{6}[ -]?\d{5}"                # Amex - 15 digits, 4-6-5
    r")\b"
)

# Rwandan mobile/landline (+250 / 07xx / 078 with optional separators) and a
# generic US-style fallback so the parser isn't only useful for one country.
PHONE_PATTERN = re.compile(
    r"(?:\+?250[\s-]?7\d{2}[\s-]?\d{3}[\s-]?\d{3})"       # +250 7xx xxx xxx
    r"|(?:\b0[7-9]\d{1}[\s-]?\d{3}[\s-]?\d{2,4}[\s-]?\d{2,3}\b)"  # 078... local
    r"|(?:\(\d{3}\)\s?\d{3}[\s-]?\d{4})"                  # (250) 722-987654 style
)

URL_PATTERN = re.compile(
    r"\bhttps?://[A-Za-z0-9.-]+(?:\.[A-Za-z]{2,})(?::\d+)?(?:/[^\s]*)?\b"
)


# ---------------------------------------------------------------------------
# 3. Validation helpers
# ---------------------------------------------------------------------------

def luhn_is_valid(card_number):
    """Standard Luhn checksum. Filters out digit strings that merely look
    like a card number (right shape) but aren't a real one."""
    digits = [int(d) for d in re.sub(r"[ -]", "", card_number)]
    if not 13 <= len(digits) <= 19:
        return False
    checksum = 0
    for i, digit in enumerate(reversed(digits)):
        if i % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def classify_alu_email(email):
    for label, pattern in ALU_DOMAIN_RULES.items():
        if pattern.search(email):
            return label
    return None


def mask_email(email):
    local, _, domain = email.partition("@")
    if len(local) <= 2:
        masked_local = local[0] + "*"
    else:
        masked_local = local[0] + "*" * (len(local) - 2) + local[-1]
    return f"{masked_local}@{domain}"


def mask_card(card_number):
    digits = re.sub(r"[ -]", "", card_number)
    return "*" * (len(digits) - 4) + digits[-4:]


# ---------------------------------------------------------------------------
# 4. Extraction
# ---------------------------------------------------------------------------

def extract(text):
    results = {
        "emails": [],
        "credit_cards": [],
        "phone_numbers": [],
        "urls": [],
    }

    for match in EMAIL_PATTERN.finditer(text):
        email = match.group(0)
        results["emails"].append({
            "masked": mask_email(email),
            "alu_category": classify_alu_email(email),
        })

    for match in CREDIT_CARD_PATTERN.finditer(text):
        card = match.group(0)
        if luhn_is_valid(card):
            results["credit_cards"].append({"masked": mask_card(card)})
        # invalid-Luhn matches are silently dropped - they looked like a
        # card but failed the checksum, so we don't treat them as real data

    for match in PHONE_PATTERN.finditer(text):
        results["phone_numbers"].append(match.group(0).strip())

    for match in URL_PATTERN.finditer(text):
        results["urls"].append(match.group(0))

    # dedupe while keeping order, phones/urls are plain strings so a set works
    results["phone_numbers"] = list(dict.fromkeys(results["phone_numbers"]))
    results["urls"] = list(dict.fromkeys(results["urls"]))

    return results


# ---------------------------------------------------------------------------
# 5. Main
# ---------------------------------------------------------------------------

def main():
    raw_text = INPUT_FILE.read_text(encoding="utf-8")
    clean_text, blocked_count = strip_hostile_lines(raw_text)

    data = extract(clean_text)

    alu_counts = {"official": 0, "alumni": 0, "si": 0, "other": 0}
    for e in data["emails"]:
        alu_counts[e["alu_category"] or "other"] += 1

    summary = {
        "blocked_hostile_lines": blocked_count,
        "emails_found": len(data["emails"]),
        "credit_cards_found": len(data["credit_cards"]),
        "phone_numbers_found": len(data["phone_numbers"]),
        "urls_found": len(data["urls"]),
        "alu_email_breakdown": alu_counts,
    }

    output = {"summary": summary, "results": data}

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_FILE.write_text(json.dumps(output, indent=2), encoding="utf-8")

    # Console summary - only masked values ever get printed
    print("=== Extraction Summary ===")
    for key, value in summary.items():
        print(f"{key}: {value}")

    print("\n=== Emails (masked) ===")
    for e in data["emails"]:
        tag = f" [{e['alu_category']}]" if e["alu_category"] else ""
        print(f"  {e['masked']}{tag}")

    print("\n=== Credit cards (masked) ===")
    for c in data["credit_cards"]:
        print(f"  {c['masked']}")

    print("\n=== Phone numbers ===")
    for p in data["phone_numbers"]:
        print(f"  {p}")

    print("\n=== URLs ===")
    for u in data["urls"]:
        print(f"  {u}")

    print(f"\nSaved full results to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
