import os
import re
import ipaddress
import joblib
import numpy as np
import pandas as pd

from urllib.parse import urlparse

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix,
    roc_auc_score,
)

# ============================================================
# CONFIGURATION
# ============================================================

DATASET_PATH = r"C:\Users\GAYATHRI\PycharmProjects\SHIELDNET\PhiUSIIL_Phishing_URL_Dataset.csv"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

MODEL_DIR = os.path.join(BASE_DIR, "ml_models")

MODEL_PATH = os.path.join(
    MODEL_DIR,
    "phishing_model.pkl"
)

FEATURE_PATH = os.path.join(
    MODEL_DIR,
    "phishing_features.pkl"
)

TEST_SIZE = 0.20
RANDOM_STATE = 42


# ============================================================
# URL FEATURE EXTRACTION
# ============================================================

SUSPICIOUS_WORDS = [
    "login",
    "signin",
    "sign-in",
    "verify",
    "verification",
    "account",
    "update",
    "secure",
    "security",
    "password",
    "passwd",
    "confirm",
    "confirmation",
    "bank",
    "banking",
    "wallet",
    "payment",
    "pay",
    "invoice",
    "billing",
    "recover",
    "recovery",
    "credential",
    "authenticate",
    "authentication",
]


def is_ip_address(hostname):
    """
    Check whether the domain/hostname is an IP address.
    """

    if not hostname:
        return 0

    try:
        ipaddress.ip_address(hostname)
        return 1
    except ValueError:
        return 0


def extract_url_features(url):
    """
    Extract features that can be calculated from the URL itself.

    IMPORTANT:
    This function must be used during both training and prediction.
    """

    url = str(url).strip()

    # Add scheme temporarily if missing
    parsed_url = urlparse(
        url if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url)
        else "http://" + url
    )

    hostname = parsed_url.hostname or ""
    path = parsed_url.path or ""
    query = parsed_url.query or ""

    # Remove leading www.
    domain_without_www = hostname.lower()

    if domain_without_www.startswith("www."):
        domain_without_www = domain_without_www[4:]

    # TLD
    tld = ""

    if "." in domain_without_www:
        tld = domain_without_www.split(".")[-1]

    # Full URL lowercase for keyword checking
    lower_url = url.lower()

    # Characters
    no_letters = sum(c.isalpha() for c in url)
    no_digits = sum(c.isdigit() for c in url)

    special_characters = sum(
        not c.isalnum() for c in url
    )

    # Obfuscated characters
    obfuscated_characters = (
        url.count("%")
        + url.count("\\")
        + url.count("//")
    )

    # Suspicious words
    suspicious_word_count = sum(
        1 for word in SUSPICIOUS_WORDS
        if word in lower_url
    )

    # Subdomains
    subdomain_count = 0

    if hostname:

        hostname_parts = hostname.split(".")

        if len(hostname_parts) > 2:

            # Ignore common www subdomain
            if hostname_parts[0].lower() == "www":
                subdomain_count = max(
                    0,
                    len(hostname_parts) - 3
                )
            else:
                subdomain_count = max(
                    0,
                    len(hostname_parts) - 2
                )

    # URL components
    path_length = len(path)
    query_length = len(query)

    # Ratio calculations
    url_length = len(url)

    letter_ratio = (
        no_letters / url_length
        if url_length > 0
        else 0
    )

    digit_ratio = (
        no_digits / url_length
        if url_length > 0
        else 0
    )

    special_char_ratio = (
        special_characters / url_length
        if url_length > 0
        else 0
    )

    obfuscation_ratio = (
        obfuscated_characters / url_length
        if url_length > 0
        else 0
    )

    # Number of dots
    dot_count = url.count(".")

    # Number of hyphens
    hyphen_count = url.count("-")

    # Number of slashes
    slash_count = url.count("/")

    # Number of @ symbols
    at_count = url.count("@")

    # Number of question marks
    question_count = url.count("?")

    # Number of equal signs
    equal_count = url.count("=")

    # Number of ampersands
    ampersand_count = url.count("&")

    # Number of percent signs
    percent_count = url.count("%")

    # HTTPS
    is_https = (
        1
        if parsed_url.scheme.lower() == "https"
        else 0
    )

    # IP address
    domain_is_ip = is_ip_address(hostname)

    # Port
    has_port = (
        1
        if parsed_url.port is not None
        else 0
    )

    # Fragment
    has_fragment = (
        1
        if parsed_url.fragment
        else 0
    )

    # Suspicious symbols
    has_at_symbol = (
        1
        if "@" in url
        else 0
    )

    has_double_slash = (
        1
        if "//" in parsed_url.path
        else 0
    )

    # Shortener domains
    shortener_domains = [
        "bit.ly",
        "tinyurl.com",
        "goo.gl",
        "t.co",
        "ow.ly",
        "is.gd",
        "buff.ly",
        "adf.ly",
        "cutt.ly",
        "tiny.cc",
        "rebrand.ly",
        "shorturl.at",
    ]

    is_url_shortener = (
        1
        if domain_without_www in shortener_domains
        else 0
    )

    # Return feature dictionary
    features = {

        # Dataset-inspired features
        "URLLength": url_length,

        "DomainLength": len(hostname),

        "IsDomainIP": domain_is_ip,

        "TLDLength": len(tld),

        "NoOfSubDomain": subdomain_count,

        "HasObfuscation": (
            1
            if obfuscated_characters > 0
            else 0
        ),

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

        # Additional URL-only features
        "DotCount": dot_count,

        "HyphenCount": hyphen_count,

        "SlashCount": slash_count,

        "AtCount": at_count,

        "PercentCount": percent_count,

        "PathLength": path_length,

        "QueryLength": query_length,

        "HasPort": has_port,

        "HasFragment": has_fragment,

        "HasAtSymbol": has_at_symbol,

        "HasDoubleSlash": has_double_slash,

        "SuspiciousWordCount": suspicious_word_count,

        "IsURLShortener": is_url_shortener,

    }

    return features


# ============================================================
# CREATE FEATURE DATAFRAME
# ============================================================

def create_feature_dataframe(url_series):

    print("\nExtracting URL features...")

    feature_rows = []

    total = len(url_series)

    for index, url in enumerate(url_series):

        features = extract_url_features(url)

        feature_rows.append(features)

        # Progress every 10,000 URLs
        if (index + 1) % 10000 == 0:
            print(
                f"Processed {index + 1:,} / {total:,} URLs"
            )

    return pd.DataFrame(feature_rows)


# ============================================================
# MAIN TRAINING FUNCTION
# ============================================================

def main():

    print("=" * 70)
    print("SHIELDNET - PHISHING URL DETECTION")
    print("=" * 70)

    # --------------------------------------------------------
    # Check dataset
    # --------------------------------------------------------

    if not os.path.exists(DATASET_PATH):

        print("\nERROR:")
        print("Dataset not found:")
        print(DATASET_PATH)

        return

    # --------------------------------------------------------
    # Create model directory
    # --------------------------------------------------------

    os.makedirs(
        MODEL_DIR,
        exist_ok=True
    )

    # --------------------------------------------------------
    # Load dataset
    # --------------------------------------------------------

    print("\nLoading dataset...")

    df = pd.read_csv(DATASET_PATH)

    print(
        f"Dataset loaded successfully."
    )

    print(
        f"Rows: {len(df):,}"
    )

    print(
        f"Columns: {len(df.columns)}"
    )

    # --------------------------------------------------------
    # Validate required columns
    # --------------------------------------------------------

    required_columns = [
        "URL",
        "label"
    ]

    for column in required_columns:

        if column not in df.columns:

            print(
                f"\nERROR: Required column '{column}' "
                f"not found in dataset."
            )

            return

    # --------------------------------------------------------
    # Remove missing URL/label rows
    # --------------------------------------------------------

    df = df.dropna(
        subset=[
            "URL",
            "label"
        ]
    ).copy()

    print(
        f"\nRows after cleaning: {len(df):,}"
    )

    # --------------------------------------------------------
    # Display label information
    # --------------------------------------------------------

    print("\nLabel distribution:")

    print(
        df["label"].value_counts()
    )

    print("\nLabel meaning:")

    print("1 = Legitimate")
    print("0 = Phishing")

    # --------------------------------------------------------
    # Extract features
    # --------------------------------------------------------

    X = create_feature_dataframe(
        df["URL"]
    )

    y = df["label"].astype(int)

    # --------------------------------------------------------
    # Check generated features
    # --------------------------------------------------------

    print("\n" + "=" * 70)
    print("GENERATED FEATURES")
    print("=" * 70)

    print(
        f"\nNumber of features: {X.shape[1]}"
    )

    print("\nFeature names:")

    for feature in X.columns:

        print(
            f" - {feature}"
        )

    # --------------------------------------------------------
    # Check missing/infinite values
    # --------------------------------------------------------

    X = X.replace(
        [np.inf, -np.inf],
        np.nan
    )

    if X.isnull().sum().sum() > 0:

        print(
            "\nMissing values detected."
        )

        X = X.fillna(0)

    # --------------------------------------------------------
    # Train/Test split
    # --------------------------------------------------------

    print("\n" + "=" * 70)
    print("TRAIN / TEST SPLIT")
    print("=" * 70)

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=TEST_SIZE,
        random_state=RANDOM_STATE,
        stratify=y
    )

    print(
        f"\nTraining samples: {len(X_train):,}"
    )

    print(
        f"Testing samples: {len(X_test):,}"
    )

    # --------------------------------------------------------
    # Create Random Forest
    # --------------------------------------------------------

    print("\n" + "=" * 70)
    print("TRAINING RANDOM FOREST")
    print("=" * 70)

    model = RandomForestClassifier(

        n_estimators=300,

        random_state=RANDOM_STATE,

        n_jobs=-1,

        class_weight="balanced",

        max_features="sqrt",

        min_samples_leaf=1
    )

    print(
        "\nTraining started..."
    )

    model.fit(
        X_train,
        y_train
    )

    print(
        "Training completed."
    )

    # --------------------------------------------------------
    # Predictions
    # --------------------------------------------------------

    print("\n" + "=" * 70)
    print("MODEL EVALUATION")
    print("=" * 70)

    y_pred = model.predict(
        X_test
    )

    y_probability = model.predict_proba(
        X_test
    )[:, 1]

    # --------------------------------------------------------
    # Metrics
    # --------------------------------------------------------

    accuracy = accuracy_score(
        y_test,
        y_pred
    )

    precision = precision_score(
        y_test,
        y_pred,
        zero_division=0
    )

    recall = recall_score(
        y_test,
        y_pred,
        zero_division=0
    )

    f1 = f1_score(
        y_test,
        y_pred,
        zero_division=0
    )

    auc = roc_auc_score(
        y_test,
        y_probability
    )

    print("\nRESULTS")
    print("-" * 50)

    print(
        f"Accuracy  : {accuracy:.4f}"
    )

    print(
        f"Precision : {precision:.4f}"
    )

    print(
        f"Recall    : {recall:.4f}"
    )

    print(
        f"F1 Score  : {f1:.4f}"
    )

    print(
        f"ROC-AUC   : {auc:.4f}"
    )

    # --------------------------------------------------------
    # Classification report
    # --------------------------------------------------------

    print("\n" + "=" * 70)
    print("CLASSIFICATION REPORT")
    print("=" * 70)

    print(
        classification_report(
            y_test,
            y_pred,
            target_names=[
                "Phishing",
                "Legitimate"
            ],
            zero_division=0
        )
    )

    # --------------------------------------------------------
    # Confusion matrix
    # --------------------------------------------------------

    print("\n" + "=" * 70)
    print("CONFUSION MATRIX")
    print("=" * 70)

    cm = confusion_matrix(
        y_test,
        y_pred
    )

    print(cm)

    print(
        "\nMatrix format:"
    )

    print(
        "[[True Negative, False Positive],"
    )

    print(
        " [False Negative, True Positive]]"
    )

    # --------------------------------------------------------
    # Feature importance
    # --------------------------------------------------------

    print("\n" + "=" * 70)
    print("TOP FEATURE IMPORTANCE")
    print("=" * 70)

    importance_df = pd.DataFrame({

        "feature": X.columns,

        "importance": model.feature_importances_

    }).sort_values(
        by="importance",
        ascending=False
    )

    print(
        importance_df.head(15).to_string(
            index=False
        )
    )

    # --------------------------------------------------------
    # Save model
    # --------------------------------------------------------

    print("\n" + "=" * 70)
    print("SAVING MODEL")
    print("=" * 70)

    joblib.dump(
        model,
        MODEL_PATH
    )

    print(
        f"\nModel saved:"
    )

    print(
        MODEL_PATH
    )

    # --------------------------------------------------------
    # Save feature columns
    # --------------------------------------------------------

    feature_data = {

        "features": list(X.columns),

        "label_mapping": {

            0: "Phishing",

            1: "Legitimate"

        },

        "dataset": "PhiUSIIL",

        "feature_type": "URL-only"

    }

    joblib.dump(
        feature_data,
        FEATURE_PATH
    )

    print(
        f"\nFeature information saved:"
    )

    print(
        FEATURE_PATH
    )

    # --------------------------------------------------------
    # Test with sample URLs
    # --------------------------------------------------------

    print("\n" + "=" * 70)
    print("SAMPLE URL TEST")
    print("=" * 70)

    sample_urls = [

        "https://www.google.com",

        "https://www.microsoft.com",

        "http://secure-login-verification-example.com/account",

        "http://paypal-login-security-example.com/verify"

    ]

    sample_features = pd.DataFrame(
        [
            extract_url_features(url)
            for url in sample_urls
        ]
    )

    sample_predictions = model.predict(
        sample_features
    )

    sample_probabilities = model.predict_proba(
        sample_features
    )

    for i, url in enumerate(sample_urls):

        prediction = sample_predictions[i]

        # Probability of phishing = class 0
        phishing_probability = (
            sample_probabilities[i][
                list(model.classes_).index(0)
            ]
        )

        if prediction == 0:

            result = "PHISHING"

        else:

            result = "LEGITIMATE"

        print("\nURL:")
        print(url)

        print(
            f"Prediction: {result}"
        )

        print(
            f"Phishing Model Probability: "
            f"{phishing_probability * 100:.2f}%"
        )

    # --------------------------------------------------------
    # Complete
    # --------------------------------------------------------

    print("\n" + "=" * 70)
    print("TRAINING COMPLETED SUCCESSFULLY")
    print("=" * 70)

    print(
        "\nShieldNet phishing model is ready."
    )

    print(
        "\nNext step:"
    )

    print(
        "Connect phishing_model.pkl "
        "to the Django phishing detection page."
    )


# ============================================================
# PROGRAM ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()