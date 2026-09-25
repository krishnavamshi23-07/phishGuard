"""
PhishGuard ML Model Training Pipeline
Trains a Random Forest URL Classifier on synthetic or benchmark datasets
(e.g., Kaggle Malicious URLs dataset or UCI Phishing Websites dataset).
Exports the trained model as a joblib file to models/rf_phishing_model.joblib.
"""

import os
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score


def generate_synthetic_benchmark_dataset(num_samples: int = 2000):
    """
    Generates a realistic benchmark training set with features matching extract_features_vector:
    [url_length, num_dots, num_hyphens, num_slashes, has_ip, has_at_symbol, digit_ratio,
     suspicious_keywords_count, is_https, entropy, subdomain_count]
    """
    np.random.seed(42)
    X = []
    y = []

    for _ in range(num_samples // 2):
        # Benign URLs
        length = np.random.normal(35, 12)
        dots = np.random.choice([1, 2, 3], p=[0.7, 0.25, 0.05])
        hyphens = np.random.choice([0, 1, 2], p=[0.8, 0.15, 0.05])
        slashes = np.random.choice([2, 3, 4], p=[0.6, 0.3, 0.1])
        has_ip = 0
        has_at = 0
        digit_ratio = np.random.uniform(0.0, 0.10)
        keywords = 0
        is_https = np.random.choice([1, 0], p=[0.95, 0.05])
        entropy = np.random.normal(3.2, 0.4)
        subdomains = np.random.choice([0, 1], p=[0.85, 0.15])

        X.append([
            max(15, length), dots, hyphens, slashes, has_ip, has_at,
            digit_ratio, keywords, is_https, max(1.0, entropy), subdomains
        ])
        y.append(0)

    for _ in range(num_samples // 2):
        # Phishing URLs
        length = np.random.normal(85, 25)
        dots = np.random.choice([2, 3, 4, 5], p=[0.1, 0.3, 0.4, 0.2])
        hyphens = np.random.choice([1, 2, 3, 4], p=[0.2, 0.3, 0.3, 0.2])
        slashes = np.random.choice([3, 4, 5, 6], p=[0.2, 0.4, 0.3, 0.1])
        has_ip = np.random.choice([0, 1], p=[0.75, 0.25])
        has_at = np.random.choice([0, 1], p=[0.85, 0.15])
        digit_ratio = np.random.uniform(0.12, 0.45)
        keywords = np.random.choice([1, 2, 3, 4], p=[0.3, 0.4, 0.2, 0.1])
        is_https = np.random.choice([1, 0], p=[0.45, 0.55])
        entropy = np.random.normal(4.4, 0.5)
        subdomains = np.random.choice([1, 2, 3, 4], p=[0.2, 0.4, 0.3, 0.1])

        X.append([
            max(20, length), dots, hyphens, slashes, has_ip, has_at,
            digit_ratio, keywords, is_https, max(1.5, entropy), subdomains
        ])
        y.append(1)

    return np.array(X), np.array(y)


def train_and_export_model(output_path: str = "models/rf_phishing_model.joblib"):
    print("[*] Generating training features and labels...")
    X, y = generate_synthetic_benchmark_dataset(num_samples=3000)

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    print(f"[*] Training Random Forest Classifier on {len(X_train)} samples...")
    clf = RandomForestClassifier(
        n_estimators=100,
        max_depth=12,
        min_samples_split=4,
        random_state=42,
        n_jobs=-1
    )
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print(f"[+] Model Accuracy: {acc * 100:.2f}%")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=["Benign", "Phishing"]))

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    joblib.dump(clf, output_path)
    print(f"[✓] Saved model artifact to: {output_path}")


if __name__ == "__main__":
    train_and_export_model()
