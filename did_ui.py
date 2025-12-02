import json
import time
from typing import Any, Dict, Optional

import requests
import streamlit as st

st.set_page_config(
    page_title="Decentralized Identity & Secure Messaging",
    layout="wide"
)

DEFAULT_BASE_URL = "https://did.zentrix.io"


def init_state():
    s = st.session_state
    s.setdefault("BASE_URL", DEFAULT_BASE_URL)

    # Test users - registration defaults
    s.setdefault("sender_email", "sender@example.com")
    s.setdefault("sender_password", "password123")
    s.setdefault("sender_label", "Alice Sender")

    s.setdefault("recipient_email", "recipient@example.com")
    s.setdefault("recipient_password", "password123")
    s.setdefault("recipient_label", "Bob Recipient")

    # Separate login fields (da korisnik posebno unosi za login)
    s.setdefault("login_sender_email", "sender@example.com")
    s.setdefault("login_sender_password", "password123")

    s.setdefault("login_recipient_email", "recipient@example.com")
    s.setdefault("login_recipient_password", "password123")

    # Auth responses
    s.setdefault("sender_login_resp", {})
    s.setdefault("recipient_login_resp", {})

    # Connection / messaging
    s.setdefault("establish_resp", {})
    s.setdefault("invitation_obj", {})      
    s.setdefault("invitation_json", "")     
    s.setdefault("accept_resp", {})
    s.setdefault("message_resp", {})

    # Inbox
    s.setdefault("messages_list", [])
    s.setdefault("selected_message_index", 0)

    # UI fields for sending message
    s.setdefault(
        "message_text",
        "Hello from Alice to Bob!"
    )
    s.setdefault("message_type", "greeting")


def api_post(path: str, body: Dict[str, Any], token: Optional[str] = None) -> Optional[Dict[str, Any]]:
    base = st.session_state["BASE_URL"].rstrip("/")
    url = f"{base}{path}"
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    try:
        r = requests.post(url, headers=headers, json=body, timeout=60)
    except Exception as e:
        st.error(f"Request error: {e}")
        return None

    if r.status_code >= 400:
        st.error(f"HTTP {r.status_code} {r.reason} for {path}")
        try:
            st.code(r.text, language="json")
        except Exception:
            st.write(r.text)
        return None

    try:
        return r.json()
    except Exception:
        st.write("Non-JSON response:")
        st.write(r.text)
        return None


def api_get(path: str, params: Optional[Dict[str, Any]] = None, token: Optional[str] = None) -> Optional[Dict[str, Any]]:
    base = st.session_state["BASE_URL"].rstrip("/")
    url = f"{base}{path}"
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    try:
        r = requests.get(url, headers=headers, params=params, timeout=60)
    except Exception as e:
        st.error(f"Request error: {e}")
        return None

    if r.status_code >= 400:
        st.error(f"HTTP {r.status_code} {r.reason} for {path}")
        try:
            st.code(r.text, language="json")
        except Exception:
            st.write(r.text)
        return None

    try:
        return r.json()
    except Exception:
        st.write("Non-JSON response:")
        st.write(r.text)
        return None


def pretty(obj: Any):
    st.code(json.dumps(obj, indent=2, ensure_ascii=False), language="json")


def get_user_id(login_resp: Dict[str, Any]) -> Optional[str]:
    user = login_resp.get("user") or {}
    doc = user.get("_doc") or {}
    uid = doc.get("_id")
    if uid:
        return uid
    return user.get("_id")


def get_access_token(login_resp: Dict[str, Any]) -> Optional[str]:
    tokens = login_resp.get("tokens") or {}
    return tokens.get("accessToken")


def get_user_did(login_resp: Dict[str, Any]) -> Optional[str]:
    user = login_resp.get("user") or {}
    doc = user.get("_doc") or {}
    return doc.get("did")


init_state()

# -------------------------------------------------------------------
# SIDEBAR
# -------------------------------------------------------------------
with st.sidebar:
    st.header("Config")
    st.text_input("BASE_URL", key="BASE_URL")

# -------------------------------------------------------------------
# TITLE
# -------------------------------------------------------------------
st.title("Decentralized Identity & Secure Messaging")

# -------------------------------------------------------------------
# 1. REGISTER USERS
# -------------------------------------------------------------------
st.header("Register users")

col1, col2 = st.columns(2)

with col1:
    st.subheader("Register sender")
    st.text_input("Email", key="sender_email")
    st.text_input("Password", key="sender_password", type="password")
    st.text_input("Label", key="sender_label")

    if st.button("Register sender user"):
        body = {
            "email": st.session_state["sender_email"],
            "password": st.session_state["sender_password"],
            "label": st.session_state["sender_label"],
            "role": "sender",
            "agent": "sender",
            "postToLedger": False
        }
        resp = api_post("/auth/register", body)
        if resp:
            st.success("Sender registered")
            with st.expander("Sender registration response"):
                pretty(resp)

with col2:
    st.subheader("Register recipient")
    st.text_input("Email ", key="recipient_email")
    st.text_input("Password ", key="recipient_password", type="password")
    st.text_input("Label ", key="recipient_label")

    if st.button("Register recipient user"):
        body = {
            "email": st.session_state["recipient_email"],
            "password": st.session_state["recipient_password"],
            "label": st.session_state["recipient_label"],
            "role": "recipient",
            "agent": "recipient",
            "postToLedger": False
        }
        resp = api_post("/auth/register", body)
        if resp:
            st.success("Recipient registered")
            with st.expander("Recipient registration response"):
                pretty(resp)

st.markdown("---")

# -------------------------------------------------------------------
# 2. LOGIN
# -------------------------------------------------------------------
st.header("Login")

col3, col4 = st.columns(2)

with col3:
    st.subheader("Login sender")
    st.text_input("Email", key="login_sender_email")
    st.text_input("Password", key="login_sender_password", type="password")

    if st.button("Login sender"):
        body = {
            "email": st.session_state["login_sender_email"],
            "password": st.session_state["login_sender_password"]
        }
        resp = api_post("/auth/signin", body)
        if resp:
            st.session_state["sender_login_resp"] = resp
            st.success("Sender logged in")
            with st.expander("Sender login response"):
                pretty(resp)

with col4:
    st.subheader("Login recipient")
    st.text_input("Email", key="login_recipient_email")
    st.text_input("Password", key="login_recipient_password", type="password")

    if st.button("Login recipient"):
        body = {
            "email": st.session_state["login_recipient_email"],
            "password": st.session_state["login_recipient_password"]
        }
        resp = api_post("/auth/signin", body)
        if resp:
            st.session_state["recipient_login_resp"] = resp
            st.success("Recipient logged in")
            with st.expander("Recipient login response"):
                pretty(resp)

st.markdown("---")

# -------------------------------------------------------------------
# 3. CONNECTION
# -------------------------------------------------------------------
st.header("Connection")

col5, col6 = st.columns(2)

with col5:
    st.subheader("Establish connection")
    if st.button("Generate invitation"):
        sender_id = get_user_id(st.session_state["sender_login_resp"])
        recipient_id = get_user_id(st.session_state["recipient_login_resp"])
        token = get_access_token(st.session_state["sender_login_resp"])

        if not sender_id or not recipient_id:
            st.error("Sender or recipient ID is missing (run logins first).")
        elif not token:
            st.error("Sender has no access token.")
        else:
            body = {
                "senderUserId": sender_id,
                "recipientUserId": recipient_id
            }
            resp = api_post("/connections/establish", body, token=token)
            if resp:
                st.session_state["establish_resp"] = resp

                inv = resp.get("invitation") or {}
                inner = inv.get("invitation") or inv  

                st.session_state["invitation_obj"] = inner
                st.session_state["invitation_json"] = json.dumps(inner, indent=2)

                st.success("Invitation created")
                with st.expander("Raw invitation (read-only)"):
                    pretty(inner)

with col6:
    st.subheader("Accept invitation")

    if not st.session_state["invitation_obj"]:
        st.info("Generate invitation first (left panel).")
    else:
        st.text("Using last generated invitation.")
        with st.expander("Current invitation (read-only)"):
            st.code(st.session_state["invitation_json"], language="json")

    if st.button("Accept connection"):
        token = get_access_token(st.session_state["recipient_login_resp"])
        recipient_id = get_user_id(st.session_state["recipient_login_resp"])
        inv = st.session_state["invitation_obj"]

        if not token:
            st.error("Recipient has no access token.")
        elif not recipient_id:
            st.error("Recipient ID is missing (login recipient first).")
        elif not inv:
            st.error("No invitation available. Generate it first.")
        else:
            body = {
                "recipientUserId": recipient_id,
                "invitation": inv
            }
            resp = api_post("/connections/accept", body, token=token)
            if resp:
                st.session_state["accept_resp"] = resp
                st.success("Connection accepted")
                with st.expander("Connection accept response"):
                    pretty(resp)

st.markdown("---")

# -------------------------------------------------------------------
# 4. MESSAGING
# -------------------------------------------------------------------
st.header("Messaging")

col_send, col_receive = st.columns(2)

# ---- SEND ----
with col_send:
    st.subheader("Send message (sender → recipient)")

    st.text_area(
        "Message text",
        key="message_text",
        height=160
    )

    st.selectbox(
        "Message type",
        options=["greeting", "status", "custom"],
        key="message_type"
    )

    if st.button("Send encrypted message"):
        sender_id = get_user_id(st.session_state["sender_login_resp"])
        recipient_id = get_user_id(st.session_state["recipient_login_resp"])
        token = get_access_token(st.session_state["sender_login_resp"])

        if not sender_id or not recipient_id:
            st.error("Sender or recipient ID is missing (logins).")
        elif not token:
            st.error("Sender has no access token.")
        else:
            plaintext = {
                "message": st.session_state["message_text"],
                "timestamp": str(int(time.time())),
                "type": st.session_state["message_type"],
            }

            body = {
                "fromUserId": sender_id,
                "toUserId": recipient_id,
                "plaintext": plaintext
            }
            resp = api_post("/messages", body, token=token)
            if resp:
                st.session_state["message_resp"] = resp
                st.success("Message sent")
                with st.expander("Plaintext payload"):
                    pretty(plaintext)
                with st.expander("Send message response"):
                    pretty(resp)

# ---- RECEIVE ----
with col_receive:
    st.subheader("Receive messages (recipient inbox)")

    recipient_login = st.session_state["recipient_login_resp"]
    recipient_did = get_user_did(recipient_login)
    recipient_token = get_access_token(recipient_login)

    st.write("Recipient DID:", recipient_did or "None")

    if st.button("Refresh inbox"):
        if not recipient_did:
            st.error("Recipient DID is missing.")
        elif not recipient_token:
            st.error("Recipient not logged in.")
        else:
            params = {"recipientDid": recipient_did}
            resp = api_get("/messages", params=params, token=recipient_token)

            if isinstance(resp, list):
                messages = resp
            else:
                messages = resp.get("messages", [])

            st.session_state["messages_list"] = messages

            if not messages:
                st.info("Inbox is empty.")
            else:
                st.success(f"Loaded {len(messages)} messages.")
                with st.expander("Raw inbox response"):
                    pretty(messages)

    messages = st.session_state.get("messages_list", [])

    if messages:
        def format_label(i: int) -> str:
            m = messages[i]
            mid = m.get("_id", f"msg_{i}")
            created = m.get("createdAt", "")
            if created:
                return f"{mid} ({created})"
            return mid

        index = st.selectbox(
            "Select a message to decrypt",
            options=list(range(len(messages))),
            format_func=format_label,
            key="selected_message_index"
        )

        selected_msg = messages[index]
        selected_id = selected_msg.get("_id")

        if st.button("Unpack selected message"):
            if not recipient_token:
                st.error("Recipient has no access token.")
            else:
                recipient_id = get_user_id(st.session_state["recipient_login_resp"])
                if not recipient_id:
                    st.error("Recipient ID missing.")
                elif not selected_id:
                    st.error("Selected message has no _id.")
                else:
                    path = f"/messages/{selected_id}/unpack"
                    body = {"asUserId": recipient_id}
                    resp = api_post(path, body, token=recipient_token)
                    if resp:
                        st.success("Decrypted message")

                        content = resp.get("content") or {}
                        msg_text = content.get("message", "(no message)")
                        msg_type = content.get("type", "")
                        msg_ts = content.get("timestamp", "")

                        st.markdown("**Decrypted message:**")
                        st.write(msg_text)

                        meta = []
                        if msg_type:
                            meta.append(f"type: `{msg_type}`")
                        if msg_ts:
                            meta.append(f"timestamp: `{msg_ts}`")
                        if meta:
                            st.caption(" · ".join(meta))
    else:
        st.info("Inbox empty. Click 'Refresh inbox'.")
