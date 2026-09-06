# Regex Data Extraction & Secure Validation

Pulls structured data (emails, credit card numbers, phone numbers, URLs) out
of messy raw text using regex, validates it, and refuses to treat hostile or
malformed input as real data.

## How to run

```bash
python3 src/main.py
```

Reads `input/raw-text.txt`, prints a summary + masked results to the
console, and writes the full structured output to
`output/sample-output.json`.

No dependencies beyond the Python standard library.

## Data types extracted

- **Emails** - general pattern, plus ALU-specific categorization into
  `official` (`@alueducation.com`), `alumni`
  (`@alumni.alueducation.com`), and `si` (`@si.alueducation.com`). Anything
  else is left uncategorized (`null`).
- **Credit card numbers** - Visa, Mastercard, Discover, and Amex number
  shapes, then run through a **Luhn checksum** so a random 16-digit string
  that merely looks like a card gets rejected.
- **Phone numbers** - Rwandan formats (`+250 7xx xxx xxx`, `078...`) plus a
  generic `(xxx) xxx-xxxx` fallback.
- **URLs** - `http://` / `https://` links only (a bare domain like
  `www.example.com` with no scheme is intentionally not treated as a URL,
  since that's indistinguishable from plain text without more context).

## Security handling

The raw text is treated as untrusted, since in the real scenario it comes
back from an external API.

1. **Pre-filter pass** (`strip_hostile_lines`): before any extraction runs,
   every line is checked against a list of patterns for script injection
   (`<script`), SQL injection (`DROP TABLE`, `' OR '1'='1`), path traversal
   (`../../`), and prompt-injection-style text (`ignore all previous
   instructions`). Any matching line is dropped entirely and only a
   **count** of blocked lines is recorded - the actual hostile text is
   never printed, logged, or forwarded anywhere, so it can't do anything
   downstream.
2. **Luhn validation** on credit cards, not just a digit-shape match, so
   junk that merely looks like a card number never gets reported as one.
3. **Masking**: extracted emails and credit card numbers are masked
   (`j*******a@alumni.alueducation.com`, `************6467`) before they
   ever reach a `print()` call or the output JSON. The unmasked value only
   ever exists transiently inside `extract()`.

**Known limitation:** the hostile-line filter works per line. A multi-line
injection attempt split across two lines (e.g. the trigger phrase on one
line, the payload on the next) can have its second line pass through
untouched - visible in the sample input/output, where
`admin@internal-system.local` still gets extracted even though the line
above it was blocked. A production version would need to buffer and scan
in blocks/paragraphs, not single lines, to close that gap.

## Sample input

`input/raw-text.txt` is a mock support-ticket export: real-looking ALU and
personal emails, test credit card numbers, Rwandan and generic phone
numbers, a few URLs, deliberately malformed data (double dots, wrong-length
numbers, broken schemes), and several hostile-input attempts (script tag,
SQL injection, path traversal, a fake "ignore previous instructions"
prompt injection) mixed in among normal lines.
