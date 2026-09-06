import json
import re
from pathlib import Path

INPUT_FILE = Path(__file__).resolve().parent.parent / "input" / "raw-text.txt"
OUTPUT_FILE = Path(__file__).resolve().parent.parent / "output" / "sample-output.json"


# block anything that looks like an attack before we even try to extract data from it
SUSPICIOUS_PATTERNS = [
    re.compile(r"<\s*script", re.IGNORECASE),          # script tags
    re.compile(r"\bDROP\s+TABLE\b", re.IGNORECASE),      # sql injection
    re.compile(r"'\s*OR\s*'1'\s*=\s*'1", re.IGNORECASE),  # classic sql injection
    re.compile(r"\.\./\.\./"),                           # path traversal
    re.compile(r"ignore\s+all\s+previous\s+instructions", re.IGNORECASE),  # prompt injection attempt
    re.compile(r"\bfetch\s*\(", re.IGNORECASE),          # trying to call out to another url
]


def strip_hostile_lines(raw_text):
    # drop the whole line if it matches something bad, just count how many got removed
    clean_lines = []
    blocked = 0
    for line in raw_text.splitlines():
        if any(p.search(line) for p in SUSPICIOUS_PATTERNS):
            blocked += 1
            continue
        clean_lines.append(line)
    return "\n".join(clean_lines), blocked


# general email regex, nothing fancy
EMAIL_PATTERN = re.compile(
    r"\b[A-Za-z0-9](?:[A-Za-z0-9._%+-]*[A-Za-z0-9])?"
    r"@[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+\b"
)

# the 3 alu domains we need to flag separately
ALU_DOMAIN_RULES = {
    "official": re.compile(r"@alueducation\.com$", re.IGNORECASE),
    "alumni": re.compile(r"@alumni\.alueducation\.com$", re.IGNORECASE),
    "si": re.compile(r"@si\.alueducation\.com$", re.IGNORECASE),
}

# visa / mastercard / discover / amex number shapes, spaces or dashes allowed
CREDIT_CARD_PATTERN = re.compile(
    r"\b(?:"
    r"4\d{3}(?:[ -]?\d{4}){3}"
    r"|5[1-5]\d{2}(?:[ -]?\d{4}){3}"
    r"|6011(?:[ -]?\d{4}){3}"
    r"|3[47]\d{2}[ -]?\d{6}[ -]?\d{5}"
    r")\b"
)

# rwanda numbers (+250 7xx or 07x) plus a generic (xxx) xxx-xxxx as fallback
PHONE_PATTERN = re.compile(
    r"(?:\+?250[\s-]?7\d{2}[\s-]?\d{3}[\s-]?\d{3})"
    r"|(?:\b0[7-9]\d{1}[\s-]?\d{3}[\s-]?\d{2,4}[\s-]?\d{2,3}\b)"
    r"|(?:\(\d{3}\)\s?\d{3}[\s-]?\d{4})"
)

URL_PATTERN = re.compile(
    r"\bhttps?://[A-Za-z0-9.-]+(?:\.[A-Za-z]{2,})(?::\d+)?(?:/[^\s]*)?\b"
)


def luhn_is_valid(card_number):
    # standard luhn check, catches stuff that looks like a card but isn't
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
    # keep first/last letter of local part, star out the middle
    local, _, domain = email.partition("@")
    if len(local) <= 2:
        masked_local = local[0] + "*"
    else:
        masked_local = local[0] + "*" * (len(local) - 2) + local[-1]
    return f"{masked_local}@{domain}"


def mask_card(card_number):
    # only show last 4 digits, rest gets starred
    digits = re.sub(r"[ -]", "", card_number)
    return "*" * (len(digits) - 4) + digits[-4:]


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
        # if luhn fails we just skip it, don't report fake-looking cards

    for match in PHONE_PATTERN.finditer(text):
        results["phone_numbers"].append(match.group(0).strip())

    for match in URL_PATTERN.finditer(text):
        results["urls"].append(match.group(0))

    # remove duplicates but keep the order they showed up in
    results["phone_numbers"] = list(dict.fromkeys(results["phone_numbers"]))
    results["urls"] = list(dict.fromkeys(results["urls"]))

    return results


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

    # print everything masked, never the raw values
    print("Extraction Summary")
    for key, value in summary.items():
        print(f"{key}: {value}")

    print("\nEmails (masked):")
    for e in data["emails"]:
        tag = f" [{e['alu_category']}]" if e["alu_category"] else ""
        print(f"  {e['masked']}{tag}")

    print("\nCredit cards (masked):")
    for c in data["credit_cards"]:
        print(f"  {c['masked']}")

    print("\nPhone numbers:")
    for p in data["phone_numbers"]:
        print(f"  {p}")

    print("\nURLs:")
    for u in data["urls"]:
        print(f"  {u}")

    print(f"\nSaved full results to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
