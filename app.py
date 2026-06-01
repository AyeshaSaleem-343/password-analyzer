import streamlit as st
import requests
import hashlib
import re
import string

def check_breach(password):
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix = sha1[:5]
    suffix = sha1[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    try:
        response = requests.get(url, timeout=5)
        hashes = response.text.splitlines()
        for h in hashes:
            h_suffix, count = h.split(":")
            if h_suffix == suffix:
                return int(count)
        return 0
    except:
        return -1

def analyze_password(password):
    score = 0
    feedback = []

    if len(password) >= 8:
        score += 1
    else:
        feedback.append("❌ Password should be at least 8 characters")

    if len(password) >= 12:
        score += 1
    else:
        feedback.append("⚠️ Longer password (12+ chars) is stronger")

    if re.search(r"[A-Z]", password):
        score += 1
    else:
        feedback.append("❌ Add uppercase letters (A-Z)")

    if re.search(r"[a-z]", password):
        score += 1
    else:
        feedback.append("❌ Add lowercase letters (a-z)")

    if re.search(r"\d", password):
        score += 1
    else:
        feedback.append("❌ Add numbers (0-9)")

    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        score += 1
    else:
        feedback.append("❌ Add special characters (!@#$%^&*)")

    common = ["password", "123456", "qwerty", "abc123", "letmein", "admin", "welcome"]
    if password.lower() in common:
        score = 0
        feedback.append("🚨 This is a very common password!")

    return score, feedback

def get_strength_label(score):
    if score <= 1:
        return "Very Weak", "#FF4444"
    elif score == 2:
        return "Weak", "#FF8800"
    elif score == 3:
        return "Moderate", "#FFCC00"
    elif score == 4:
        return "Strong", "#88CC00"
    else:
        return "Very Strong", "#00CC44"

st.set_page_config(
    page_title="Password Analyzer",
    page_icon="🔐",
    layout="centered"
)

st.title("🔐 Password Strength Analyzer")
st.markdown("Check your password strength and see if it has been exposed in a data breach!")

password = st.text_input(
    "Enter your password",
    type="password",
    placeholder="Type your password here..."
)

show_password = st.checkbox("Show password")
if show_password and password:
    st.code(password)

if password:
    score, feedback = analyze_password(password)
    label, color = get_strength_label(score)

    st.divider()

    st.markdown(f"### Strength: <span style='color:{color}'>{label}</span>", unsafe_allow_html=True)
    progress = score / 6
    st.progress(progress)

    col1, col2, col3 = st.columns(3)
    col1.metric("Score", f"{score}/6")
    col2.metric("Length", len(password))
    col3.metric("Characters", len(set(password)))

    if feedback:
        st.subheader("💡 Suggestions")
        for f in feedback:
            st.write(f)

    st.divider()
    st.subheader("🔍 Breach Check")
    st.write("Checking if this password has appeared in known data breaches...")

    breach_count = check_breach(password)
    if breach_count == -1:
        st.warning("⚠️ Could not connect to breach database. Check your internet.")
    elif breach_count == 0:
        st.success("✅ Great news! This password was NOT found in any known data breach!")
    else:
        st.error(f"🚨 DANGER! This password has been found {breach_count:,} times in data breaches! Change it immediately!")

    st.divider()
    st.subheader("📊 Password Analysis")
    has_upper = "✅" if re.search(r"[A-Z]", password) else "❌"
    has_lower = "✅" if re.search(r"[a-z]", password) else "❌"
    has_digit = "✅" if re.search(r"\d", password) else "❌"
    has_special = "✅" if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password) else "❌"

    c1, c2 = st.columns(2)
    with c1:
        st.write(f"{has_upper} Uppercase Letters")
        st.write(f"{has_lower} Lowercase Letters")
    with c2:
        st.write(f"{has_digit} Numbers")
        st.write(f"{has_special} Special Characters")
else:
    st.info("👆 Enter a password above to analyze it!")
    st.markdown("""
    ### What this tool checks:
    - ✅ Password length
    - ✅ Uppercase & lowercase letters
    - ✅ Numbers & special characters
    - ✅ Common password detection
    - ✅ Data breach database (HaveIBeenPwned)
    """)