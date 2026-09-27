"""
SIH26 - Decentralized Access Ledger (DAL)
Streamlit Dashboard — built for a LIVE demo flow:
1. Register a couple of users
2. Request some access events (mix of normal + suspicious)
3. Show the chain is valid
4. Hit "tamper" on a past block
5. Show integrity check now fails — this is the moment that sells the idea

Run with: streamlit run dashboard.py
"""

import streamlit as st
from dal_system import DALSystem

st.set_page_config(page_title="Decentralized Access Ledger", page_icon="🔗", layout="wide")

if "system" not in st.session_state:
    st.session_state.system = DALSystem()
    st.session_state.registered_users = []

system = st.session_state.system

st.title("🔗 Decentralized Access Ledger (DAL)")
st.caption("SIH26 — Blockchain-based Identity, Access Control & Digital Asset Management (BEL)")

st.warning(
    "**Honest scoping:** this is a single-node hash-chain demonstrating blockchain's "
    "core tamper-evidence mechanism (cryptographic hash-linking + signed identity). "
    "Production deployment would run on a distributed network (e.g. Hyperledger Fabric) "
    "across BEL's actual infrastructure nodes with real consensus. This prototype proves "
    "the data structure and detection logic — the part that matters for this demo."
)

col_left, col_right = st.columns([1, 1])

with col_left:
    st.subheader("1. Register Users")
    new_user = st.text_input("User ID to register", value="u001")
    if st.button("Register User"):
        fp = system.register_user(new_user)
        st.session_state.registered_users.append(new_user)
        st.success(f"Registered {new_user} — public key fingerprint: `{fp}`")

    if st.session_state.registered_users:
        st.write("**Registered users:**", ", ".join(st.session_state.registered_users))

    revoke_user = st.selectbox(
        "Revoke a user (simulates offboarding/compromised identity)",
        options=[""] + st.session_state.registered_users,
    )
    if st.button("Revoke Selected User") and revoke_user:
        system.revoke_user(revoke_user)
        st.error(f"{revoke_user} has been revoked.")

with col_right:
    st.subheader("2. Request Access")
    if st.session_state.registered_users:
        user_id = st.selectbox("User requesting access", options=st.session_state.registered_users)
        resource = st.text_input("Resource", value="server-rack-3")
        action = st.selectbox("Action", options=["ACCESS_GRANTED", "ACCESS_DENIED", "ACCESS_ATTEMPT"])

        if st.button("Submit Access Event"):
            result = system.request_access(user_id, resource, action)
            if "error" in result:
                st.error(result["error"])
            else:
                risk = result["event"]["risk_level"]
                icon = "🔴" if risk == "HIGH" else "🟡" if risk == "MEDIUM" else "🟢"
                st.success(f"Event written to block #{result['block_index']} — {icon} Risk: {risk}")
                if result["event"]["flags"]:
                    for f in result["event"]["flags"]:
                        st.write(f"⚠️ {f}")
    else:
        st.info("Register at least one user first.")

st.divider()

st.subheader("3. Chain Integrity")
integrity = system.verify_chain()
if integrity["valid"]:
    st.success(f"✅ {integrity['reason']}")
else:
    st.error(f"❌ TAMPERING DETECTED — {integrity['reason']}")

col_a, col_b = st.columns([1, 3])
with col_a:
    chain_len = len(system.get_chain())
    tamper_index = st.number_input(
        "Block index to tamper with (demo only)",
        min_value=0, max_value=max(chain_len - 1, 0), value=min(1, max(chain_len - 1, 0)),
    )
    if st.button("🔨 Simulate Attacker Tampering"):
        system.simulate_tamper(tamper_index, fake_action="ACCESS_GRANTED")
        st.rerun()

st.divider()

st.subheader("4. Full Ledger (Blockchain View)")
for block in system.get_chain():
    with st.expander(f"Block #{block['index']} — hash: {block['hash'][:16]}..."):
        st.json(block)

if st.button("🔄 Reset Demo (fresh ledger)"):
    st.session_state.system = DALSystem()
    st.session_state.registered_users = []
    st.rerun()
