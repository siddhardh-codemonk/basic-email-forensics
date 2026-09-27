# Decentralized Access Ledger (DAL)

**PS match:** "Blockchain-based platform for identity, access control &
digital asset management" — BEL, SIH26

A working prototype: every access grant/deny/attempt gets written to a
hash-chained ledger, signed with the requesting user's private key. Try
to edit a past record and the chain integrity check catches it instantly
and tells you exactly which block broke.

## What's built (all working, tested)

| Module | What it does |
|---|---|
| `ledger.py` | Core hash-chain — each block stores the hash of the previous block; `verify_integrity()` walks the whole chain and pinpoints exactly where tampering happened |
| `identity.py` | RSA keypair registry — every user gets signed/verified access events, so the ledger proves *who* requested *what*, not just a claimed username |
| `anomaly.py` | Rule-based flags: revoked identity attempting access, invalid signature, off-hours access |
| `dal_system.py` | Orchestrator — wires the three above into one flow: register → request access → anomaly-check → write to chain → verify |
| `dashboard.py` | Streamlit UI built for a **live demo**: register users, submit access events, watch risk flags appear, then hit "Simulate Attacker Tampering" and watch the integrity check fail in real time |

## ⚠️ Honest scoping — say this upfront in the pitch, don't wait to be asked

This is a **single-node hash-chain**, not a distributed multi-node
blockchain with consensus. It demonstrates the core mechanism that makes
blockchain useful here — cryptographic hash-linking that makes tampering
detectable — running on one process.

**What it does NOT have:** multiple nodes, a consensus protocol (proof-of-work/
proof-of-stake), or network-level Byzantine fault tolerance.

**Why that's fine to say out loud:** no team is standing up a real
Hyperledger Fabric cluster in a hackathon window. What you're proving is
that you understand *what property blockchain actually gives you*
(immutability via hash-chaining + non-repudiation via signatures) and can
demonstrate it live. Judges who know blockchain will ask "how many
nodes / what consensus" regardless — answering that proactively before
they ask reads as competence, not a gap. Have this ready:

> "This prototype demonstrates the core tamper-evidence mechanism on a
> single node. A production deployment for BEL would run this same
> ledger logic across a permissioned Hyperledger Fabric network on their
> internal infrastructure nodes, with PBFT or Raft consensus so no single
> compromised node can rewrite history."

## How to run it

```bash
cd sih-dal
pip install -r requirements.txt
# add --break-system-packages if pip complains about externally-managed environment

streamlit run dashboard.py
```
Opens at `http://localhost:8501`.

**Command-line version (no UI, for a quick sanity check):**
```bash
python3 dal_system.py
```
Prints a full scripted run: register 2 users, one legit access, one
revoked-user access attempt (correctly flagged HIGH risk), chain valid,
then simulated tampering with the integrity check catching it.

## Demo script (do this order for judges)

1. Register 2 users (`u001`, `u002`)
2. Submit a normal access event for `u001` → show it lands in the chain, LOW/MEDIUM risk
3. Revoke `u002`
4. Submit an access event for `u002` → show it gets flagged HIGH risk
   ("REVOKED IDENTITY attempted access") and still gets logged — that's
   the point, you want a record of the attempted breach too
5. Show the chain integrity check passes (green)
6. Hit "Simulate Attacker Tampering" on an earlier block
7. Show the integrity check now fails and names the exact block — **this
   is the moment that sells the idea**, don't rush past it

## Known gaps / what to say if judges ask "what's not done yet"

- Single-node, not distributed — see honest scoping section above
- No persistent storage — ledger resets when the dashboard restarts
  (real version would write to disk/DB, this is in-memory for demo speed)
- Anomaly rules are simple (revoked/off-hours/bad-signature) — production
  version would add pattern-based anomaly detection (unusual resource
  combos, access velocity, etc.)
- No actual "digital asset management" piece yet — the PS mentions this
  alongside identity/access; current build is access-control only. If
  there's time: extend the ledger schema to also track asset
  custody/transfer events, same hash-chain mechanism.
