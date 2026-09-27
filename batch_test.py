"""
Batch test runner — scores every .eml in sample_emails/ and prints a
comparison table. Good for demoing to judges: "here's obvious phishing,
here's subtle phishing, here's legit mail, and here's how the scores
separate them."
"""

import os
import glob
from risk_scorer import score_email

# body text per sample, since .eml body extraction for the language module
# isn't wired up yet (dashboard takes body as manual paste for now) —
# keyed by filename so batch mode can test language signals too
SAMPLE_BODIES = {
    "phishing_sample.eml": (
        "Click here to verify: http://paypa1-verify.com/secure/login "
        "We have detected unusual activity."
    ),
    "phishing_sample_2_spf_pass.eml": (
        "Your Microsoft 365 password will expire in 3 days. Please confirm "
        "your identity and update your password immediately."
    ),
    "legit_sample_google.eml": (
        "Here's a quick summary of your Google Drive storage for this month."
    ),
}


def run_batch():
    sample_dir = os.path.join(os.path.dirname(__file__), "sample_emails")
    files = sorted(glob.glob(os.path.join(sample_dir, "*.eml")))

    print(f"{'File':<40} {'Score':>6}  {'Verdict'}")
    print("-" * 90)

    for path in files:
        fname = os.path.basename(path)
        body = SAMPLE_BODIES.get(fname, "")
        result = score_email(path, body)
        print(f"{fname:<40} {result['score']:>5}  {result['verdict']}")

    print("-" * 90)
    print(f"Tested {len(files)} sample(s).")


if __name__ == "__main__":
    run_batch()
