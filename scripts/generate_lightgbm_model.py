#!/usr/bin/env python3
"""
Generate synthetic LightGBM model for SVALINN threat scoring.
This mimics the Node.js v8.3 model trained on 2000 samples.
"""

import numpy as np
import lightgbm as lgb
from sklearn.model_selection import train_test_split
import os

def generate_synthetic_data(n_samples=2000):
    """
    Generate synthetic threat detection data.
    
    Features (10 total):
    0. request_rate: requests per minute
    1. path_entropy: shannon entropy of path
    2. payload_size: normalized payload size
    3. error_rate: 4xx/5xx error rate
    4. geo_risk: country risk score
    5. ua_age: user agent age
    6. time_of_day: hour normalized
    7. is_suspicious_ua: bool
    8. has_payload: bool
    9. is_known_scanner: bool
    """
    np.random.seed(42)
    
    # Generate benign traffic (60%)
    n_benign = int(n_samples * 0.6)
    benign_data = np.array([
        np.random.normal(1.0, 0.5, n_benign),   # Low request rate
        np.random.normal(0.3, 0.1, n_benign),   # Low entropy
        np.random.uniform(0, 0.3, n_benign),    # Small payloads
        np.random.uniform(0, 0.1, n_benign),    # Low error rate
        np.random.uniform(0, 0.3, n_benign),    # Low geo risk
        np.random.uniform(0, 0.5, n_benign),    # Modern UA
        np.random.uniform(0, 1, n_benign),      # Random time
        np.random.binomial(1, 0.1, n_benign),   # Rarely suspicious UA
        np.random.binomial(1, 0.3, n_benign),   # Sometimes has payload
        np.zeros(n_benign),                      # Not known scanner
    ]).T
    benign_labels = np.zeros(n_benign)
    
    # Generate malicious traffic (40%)
    n_malicious = n_samples - n_benign
    malicious_data = np.array([
        np.random.normal(10.0, 5.0, n_malicious),  # High request rate
        np.random.normal(0.7, 0.2, n_malicious),   # High entropy
        np.random.uniform(0.1, 1.0, n_malicious),  # Variable payloads
        np.random.uniform(0.3, 0.9, n_malicious),  # High error rate
        np.random.uniform(0.5, 1.0, n_malicious),  # High geo risk
        np.random.uniform(0.5, 1.0, n_malicious),  # Old/suspicious UA
        np.random.uniform(0, 1, n_malicious),      # Random time (attacks 24/7)
        np.random.binomial(1, 0.8, n_malicious),   # Often suspicious UA
        np.random.binomial(1, 0.7, n_malicious),   # Often has payload
        np.random.binomial(1, 0.6, n_malicious),   # Often known scanner
    ]).T
    malicious_labels = np.ones(n_malicious)
    
    # Combine and shuffle
    X = np.vstack([benign_data, malicious_data])
    y = np.hstack([benign_labels, malicious_labels])
    
    # Clip values to valid ranges
    X = np.clip(X, 0, None)
    X[:, 7:] = np.clip(X[:, 7:], 0, 1)  # Binary features
    
    return X, y

def train_lightgbm_model(X, y):
    """Train LightGBM model for threat classification."""
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )
    
    # Train LightGBM classifier
    model = lgb.LGBMClassifier(
        n_estimators=100,
        max_depth=5,
        learning_rate=0.1,
        num_leaves=31,
        random_state=42,
        verbose=-1
    )
    
    print("Training LightGBM model on {} samples...".format(len(X_train)))
    model.fit(X_train, y_train)
    
    # Evaluate
    train_score = model.score(X_train, y_train)
    test_score = model.score(X_test, y_test)
    
    print(f"Training accuracy: {train_score:.3f}")
    print(f"Test accuracy: {test_score:.3f}")
    
    return model

def save_model_for_go(model, output_path):
    """Save model in text format readable by Go leaves library."""
    # Save as text format (compatible with leaves)
    model.booster_.save_model(output_path)
    print(f"Model saved to: {output_path}")
    print(f"Model can be loaded in Go using: leaves.LGEnsembleFromFile()")

if __name__ == "__main__":
    print("="*60)
    print("SVALINN LightGBM Threat Scorer - Model Generator")
    print("Mimicking Node.js v8.3 training (2000 samples)")
    print("="*60)
    print()
    
    # Generate synthetic data
    X, y = generate_synthetic_data(2000)
    print(f"Generated {len(X)} samples")
    print(f"  Benign: {np.sum(y == 0)}")
    print(f"  Malicious: {np.sum(y == 1)}")
    print()
    
    # Train model
    model = train_lightgbm_model(X, y)
    print()
    
    # Save model
    output_dir = os.path.join(os.path.dirname(__file__), "..", "data", "models")
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, "threat_scorer.txt")
    
    save_model_for_go(model, output_path)
    print()
    print("✅ Model generation complete!")
    print()
    print("Next steps:")
    print("1. Copy model to VPS: data/models/threat_scorer.txt")
    print("2. Build SVALINN with new threat scorer")
    print("3. Deploy and verify ML scoring in logs")
