import os
import re
import ipaddress
import joblib
import pandas as pd
from urllib.parse import urlparse

# ============================================================
# PATHS & MODEL LOADING
# ============================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

MODEL_PATH = os.path.join(BASE_DIR, "ml_models", "phishing_model.pkl")
FEATURE_PATH = os.path.join(BASE_DIR, "ml_models", "phishing_features.pkl")

try:
    phishing_model = joblib.load(MODEL_PATH)
    feature_information = joblib.load(FEATURE_PATH)
    FEATURE_COLUMNS = feature_information["features"]
    MODEL_LOADED = True
    print("ShieldNet phishing model loaded successfully.")
except Exception as e:
    phishing_model = None
    FEATURE_COLUMNS = []
    MODEL_LOADED = False
    print("ERROR loading phishing model:", e)

# ============================================================
# SUSPICIOUS WORDS
# ============================================================

SUSPICIOUS_WORDS = [
    "login", "signin", "sign-in", "verify", "verification",
    "account", "update", "secure", "security", "password",
    "passwd", "confirm", "confirmation", "bank", "banking",
    "wallet", "payment", "pay", "invoice", "billing",
    "recover", "recovery", "credential", "authenticate", "authentication"
]

# ============================================================
# HELPER FUNCTIONS
# ============================================================

def is_ip_address(hostname):
    if not hostname:
        return 0
    try:
        ipaddress.ip_address(hostname)
        return 1
    except ValueError:
        return 0

# ============================================================
# URL FEATURE EXTRACTION
# ============================================================

def extract_url_features(url):
    url = str(url).strip()

    if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        parsed_url = urlparse(url)
    else:
        url = "https://" + url
        parsed_url = urlparse(url)

    hostname = parsed_url.hostname or ""
    path = parsed_url.path or ""
    query = parsed_url.query or ""

    domain_without_www = hostname.lower()
    if domain_without_www.startswith("www."):
        domain_without_www = domain_without_www[4:]

    tld = ""
    if "." in domain_without_www:
        tld = domain_without_www.split(".")[-1]

    lower_url = url.lower()

    no_letters = sum(c.isalpha() for c in url)
    no_digits = sum(c.isdigit() for c in url)
    special_characters = sum(not c.isalnum() for c in url)

    obfuscated_characters = url.count("%") + url.count("\\") + url.count("//")

    suspicious_word_count = sum(1 for word in SUSPICIOUS_WORDS if word in lower_url)

    subdomain_count = 0
    if hostname:
        hostname_parts = hostname.split(".")
        if len(hostname_parts) > 2:
            if hostname_parts[0].lower() == "www":
                subdomain_count = max(0, len(hostname_parts) - 3)
            else:
                subdomain_count = max(0, len(hostname_parts) - 2)

    url_length = len(url)
    letter_ratio = (no_letters / url_length) if url_length > 0 else 0
    digit_ratio = (no_digits / url_length) if url_length > 0 else 0
    special_char_ratio = (special_characters / url_length) if url_length > 0 else 0
    obfuscation_ratio = (obfuscated_characters / url_length) if url_length > 0 else 0

    dot_count = url.count(".")
    hyphen_count = url.count("-")
    slash_count = url.count("/")
    at_count = url.count("@")
    question_count = url.count("?")
    equal_count = url.count("=")
    ampersand_count = url.count("&")
    percent_count = url.count("%")

    is_https = 1 if parsed_url.scheme.lower() == "https" else 0
    domain_is_ip = is_ip_address(hostname)

    try:
        has_port = 1 if parsed_url.port is not None else 0
    except ValueError:
        has_port = 0

    has_fragment = 1 if parsed_url.fragment else 0
    has_at_symbol = 1 if "@" in url else 0
    has_double_slash = 1 if "//" in parsed_url.path else 0

    shortener_domains = [
        "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly",
        "is.gd", "buff.ly", "adf.ly", "cutt.ly", "tiny.cc",
        "rebrand.ly", "shorturl.at"
    ]
    is_url_shortener = 1 if domain_without_www in shortener_domains else 0

    features = {
        "URLLength": url_length,
        "DomainLength": len(hostname),
        "IsDomainIP": domain_is_ip,
        "TLDLength": len(tld),
        "NoOfSubDomain": subdomain_count,
        "HasObfuscation": 1 if obfuscated_characters > 0 else 0,
        "NoOfObfuscatedChar": obfuscated_characters,
        "ObfuscationRatio": obfuscation_ratio,
        "NoOfLettersInURL": no_letters,
        "LetterRatioInURL": letter_ratio,
        "NoOfDegitsInURL": no_digits,
        "DegitRatioInURL": digit_ratio,
        "NoOfEqualsInURL": equal_count,
        "NoOfQMarkInURL": question_count,
        "NoOfAmpersandInURL": ampersand_count,
        "NoOfOtherSpecialCharsInURL": (
            special_characters
            - dot_count
            - hyphen_count
            - slash_count
            - at_count
            - question_count
            - equal_count
            - ampersand_count
        ),
        "SpacialCharRatioInURL": special_char_ratio,
        "IsHTTPS": is_https,
        "DotCount": dot_count,
        "HyphenCount": hyphen_count,
        "SlashCount": slash_count,
        "AtCount": at_count,
        "PercentCount": percent_count,
        "PathLength": len(path),
        "QueryLength": len(query),
        "HasPort": has_port,
        "HasFragment": has_fragment,
        "HasAtSymbol": has_at_symbol,
        "HasDoubleSlash": has_double_slash,
        "SuspiciousWordCount": suspicious_word_count,
        "IsURLShortener": is_url_shortener,
    }

    return features

# ============================================================
# PREDICTION LOGIC
# ============================================================

def predict_phishing(url):
    if phishing_model is None:
        raise Exception("Phishing ML model is not loaded.")

    features = extract_url_features(url)
    feature_df = pd.DataFrame([features])
    feature_df = feature_df[FEATURE_COLUMNS]

    prediction = phishing_model.predict(feature_df)[0]
    probabilities = phishing_model.predict_proba(feature_df)[0]

    classes = list(phishing_model.classes_)
    phishing_index = classes.index(0)
    legitimate_index = classes.index(1)

    phishing_probability = probabilities[phishing_index]
    legitimate_probability = probabilities[legitimate_index]

    # 0 = Phishing, 1 = Legitimate
    result = "PHISHING" if prediction == 0 else "LEGITIMATE"

    return {
        "result": result,
        "prediction": int(prediction),
        "phishing_probability": round(phishing_probability * 100, 2),
        "legitimate_probability": round(legitimate_probability * 100, 2),
        "features": features,
    }