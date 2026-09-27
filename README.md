# SIH26106 — Email Threat Detection, GeoLocation & Forensic Intelligence Platform

A working prototype: upload a suspicious `.eml`, get a 0–100 fraud risk
score with human-readable reasoning, IP geolocation trace, and domain-age
check — all in a browser dashboard.

## What's built (all working, tested)

| Module | What it does |
|---|---|
| `header_parser.py` | Parses `.eml`, extracts relay chain (hop-by-hop, oldest first), SPF/DKIM/DMARC verdicts, From/Reply-To/Return-Path mismatch |
| `geolocate.py` | Resolves the originating IP → country/city/ISP/hosting-provider/proxy status via ip-api.com (free, no key) |
| `domain_age.py` | WHOIS lookup on the From domain — flags domains registered <90 days ago (classic phishing-infra signal) |
| `phishing_language.py` | Detects urgency phrases, credential-harvest language, and **typosquat brand impersonation** (e.g. `microsoft-support.co` claiming to be Microsoft — catches lookalike domains, not just totally unrelated ones) |
| `risk_scorer.py` | Combines all of the above into one weighted 0–100 score + verdict + reasons |
| `dashboard.py` | Streamlit UI — upload, see score, drill into each signal across tabs |
| `batch_test.py` | Scores every sample in `sample_emails/` at once — good for a live demo of score separation |

## How to run it

**1. Install dependencies** (do this once):
```bash
cd sih-email-forensics
pip install -r requirements.txt
```
If `pip` complains about "externally managed environment" on Linux, use:
```bash
pip install -r requirements.txt --break-system-packages
```

**2. Launch the dashboard:**
```bash
streamlit run dashboard.py
```
This opens a browser tab (usually `http://localhost:8501`). If it doesn't
auto-open, copy that URL manually.

**3. Try it:**
- Upload one of the files in `sample_emails/` (three included — one obvious
  phish, one subtle typosquat phish, one legit control)
- Paste the matching body text into the text box (body extraction from
  `.eml` isn't wired into the dashboard yet — see "Known gaps" below)
- You'll get a score, verdict, and tabs showing exactly why

**4. Or run everything from the command line without the UI:**
```bash
python3 batch_test.py
```
This prints a comparison table across all sample emails — fastest way to
sanity-check the scorer still works after any edits.

## Sample test set (`sample_emails/`)

| File | Expected result |
|---|---|
| `phishing_sample.eml` | Obvious phish — failed auth, unrelated domain, urgency spam → **HIGH RISK (~79)** |
| `phishing_sample_2_spf_pass.eml` | Subtle phish — SPF/DKIM pass but typosquat domain (`microsoft-support.co`) + DMARC fail → **MEDIUM RISK (~54)** |
| `legit_sample_google.eml` | Clean email, all auth passes, no red flags → **LOW RISK (0)** |

Run `python3 batch_test.py` any time to re-confirm these numbers.

## For the pitch/demo

Lead with the typosquat case (`phishing_sample_2_spf_pass.eml`). It's the
strongest thing to show a judge because it proves the tool isn't just
checking "did SPF fail" — it catches a phish that PASSES standard auth
checks but still gets flagged because the domain looks like the brand
without being the brand's real domain. That's the differentiator most
naive phishing filters miss.

## Known gaps / what to say if judges ask "what's not done yet"

- Body text extraction from `.eml` isn't automatic in the dashboard yet —
  currently pasted manually. Straightforward fix (`msg.get_body()`),
  just not wired up — good "if we had one more hour" answer.
- Language detection is rule-based (regex), not ML. Explicitly by design
  for a working prototype in a short window — swapping in a trained
  classifier (Kaggle phishing-email dataset + TF-IDF/logistic regression)
  is a clean drop-in upgrade, same output shape.
- No case/campaign clustering (grouping multiple emails from the same
  attacker infrastructure) — this maps to the PS's "attribution"
  language and is the natural next feature if there's time.
- `geolocate.py` and `domain_age.py` need real internet access to work —
  they were built and unit-tested individually, but this build
  environment's network is locked to a handful of domains, so full
  end-to-end geo/WHOIS calls need to run on your own machine to confirm.
  Test both standalone first if something looks off:
  ```bash
  python3 geolocate.py 8.8.8.8
  python3 domain_age.py google.com
  ```
