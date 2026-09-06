# Regex Data Extraction & Secure Validation

Pulls emails, credit card numbers, phone numbers and URLs out of raw text
using regex, checks they're actually valid, and drops anything that looks
like an attack instead of trying to process it.

## Running it

```
python3 src/main.py
```

It reads `input/raw-text.txt`, prints the results (masked) to the console,
and writes the full thing to `output/sample-output.json`. Just standard
library, nothing to install.

## What it extracts

- Emails - also checks if it's an ALU address and tags it as `official`
  (@alueducation.com), `alumni` (@alumni.alueducation.com) or `si`
  (@si.alueducation.com)
- Credit cards - matches Visa/Mastercard/Discover/Amex number shapes, then
  runs a Luhn check so random digit strings that just look like a card
  don't get counted
- Phone numbers - Rwandan formats mostly (+250 7xx / 07x), plus a generic
  (xxx) xxx-xxxx pattern
- URLs - has to start with http:// or https://

## Security stuff

The text is treated as untrusted since it's coming from an external API in
the scenario. Before any extraction happens, every line gets checked
against a list of patterns for things like script tags, SQL injection,
path traversal, and prompt-injection style text ("ignore all previous
instructions..."). If a line matches, it gets dropped completely and only
a count is kept - the actual malicious text never gets printed or saved
anywhere.

Credit cards also get run through Luhn validation, not just matched by
shape. And both emails and card numbers get masked before they're ever
printed or written to the output file, so the full values never show up in
console logs or in the JSON.

One thing I noticed while testing: the filter works per line, so if
someone splits an attack across two lines (trigger phrase on one line,
payload on the next), the second line can slip through since it looks
harmless on its own. You can actually see this in the sample output -
`admin@internal-system.local` still gets picked up even though the line
above it got blocked. Fixing that properly would mean scanning in blocks
of text instead of single lines.

## Sample input

`input/raw-text.txt` is a made-up support ticket export - fake ALU/personal
emails, test credit card numbers, some Rwandan phone numbers, a few URLs,
some intentionally broken/malformed data, and a handful of attack attempts
mixed in to test that the filtering actually works.
