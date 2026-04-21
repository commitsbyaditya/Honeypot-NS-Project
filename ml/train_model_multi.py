"""
train_model_multi.py - Multi-Attack Classification Training Pipeline
=====================================================================

This module trains a machine learning classifier on attack data from
multiple attack types (SSH, PortScan, DNS, ARP, ICMP).

Enhanced from original train_model.py to support:
  - 5 attack types with unified feature extraction
  - 13 attack class labels
  - Per-attack-type evaluation metrics
  - Feature importance analysis

Usage:
    python ml/train_model_multi.py
"""

import os
import sys
import argparse
import pandas as pd
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, StratifiedKFold
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import (
    classification_report, accuracy_score, confusion_matrix,
    precision_recall_fscore_support
)

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from ml.feature_extractors import extract_features, get_feature_columns
from ml.labeling_rules import generate_labels, get_all_labels
from ml.data_loader import load_mixed_csv, get_attack_type_stats


# ═══════════════════════════════════════════════════════════════════════════
# PATH CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════
_CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_PATH = os.path.join(_CURRENT_DIR, "..", "data", "attack_logs.csv")
MODEL_PATH = os.path.join(_CURRENT_DIR, "..", "models", "attack_model.pkl")
LABEL_ENCODER_PATH = os.path.join(_CURRENT_DIR, "..", "models", "label_encoder.pkl")

# Hyperparameters
TEST_SIZE = 0.2
RANDOM_STATE = 42
N_ESTIMATORS = 100


def load_data(data_path: str = DATA_PATH) -> pd.DataFrame:
    """
    Load attack log data from CSV using unified data loader.
    
    Args:
        data_path: Path to CSV file
    
    Returns:
        DataFrame with attack session data in unified format
    """
    df = load_mixed_csv(data_path, verbose=True)
    
    # Show attack type distribution
    stats = get_attack_type_stats(df)
    if stats:
        print("\nAttack Type Distribution:")
        for attack_type, info in stats.items():
            print(f"  {attack_type}: {info['count']} ({info['percentage']:.1f}%)")
    
    return df


def train_multi_attack_model(
    df: pd.DataFrame,
    test_size: float = TEST_SIZE,
    n_estimators: int = N_ESTIMATORS
) -> tuple:
    """
    Train a multi-attack classification model.
    
    Pipeline:
      1. Extract features (handles all attack types)
      2. Generate labels (based on labeling rules)
      3. Encode labels
      4. Train/test split
      5. Train Random Forest
      6. Evaluate
    
    Args:
        df: DataFrame with attack session data
        test_size: Fraction for test set
        n_estimators: Number of trees in forest
    
    Returns:
        Tuple of (model, label_encoder, accuracy, X_test, y_test)
    """
    print("\n" + "=" * 70)
    print("MULTI-ATTACK CLASSIFICATION TRAINING")
    print("=" * 70)
    
    # Step 1: Extract features
    print("\n[Step 1] Extracting features...")
    X = extract_features(df)
    feature_columns = X.columns.tolist()
    print(f"  Features: {len(feature_columns)} columns")
    print(f"  {feature_columns[:5]}... (showing first 5)")
    
    # Step 2: Generate labels
    print("\n[Step 2] Generating labels...")
    y_labels = generate_labels(df)
    print(f"  Label distribution:")
    for label, count in y_labels.value_counts().items():
        print(f"    {label}: {count}")
    
    # Step 2b: Handle rare classes (need at least 2 samples for stratified split)
    MIN_SAMPLES = 2
    label_counts = y_labels.value_counts()
    rare_classes = label_counts[label_counts < MIN_SAMPLES].index.tolist()
    
    if rare_classes:
        print(f"\n[Step 2b] Handling rare classes (< {MIN_SAMPLES} samples)...")
        print(f"  Rare classes: {rare_classes}")
        
        # Option 1: Duplicate rare samples to meet minimum
        for rare_class in rare_classes:
            rare_mask = y_labels == rare_class
            rare_indices = y_labels[rare_mask].index.tolist()
            
            # Duplicate the rare samples
            for idx in rare_indices:
                X = pd.concat([X, X.loc[[idx]]], ignore_index=True)
                y_labels = pd.concat([y_labels, pd.Series([rare_class])], ignore_index=True)
            
            print(f"    Duplicated {rare_class}: 1 -> 2 samples")
        
        print(f"  New total samples: {len(X)}")
    
    # Step 3: Encode labels
    print("\n[Step 3] Encoding labels...")
    label_encoder = LabelEncoder()
    y = label_encoder.fit_transform(y_labels)
    print(f"  Classes: {list(label_encoder.classes_)}")
    
    # Step 4: Train/test split
    print("\n[Step 4] Splitting data...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=test_size,
        random_state=RANDOM_STATE,
        stratify=y
    )
    print(f"  Training set: {len(X_train)} samples")
    print(f"  Test set: {len(X_test)} samples")
    
    # Step 5: Train model
    print("\n[Step 5] Training Random Forest...")
    model = RandomForestClassifier(
        n_estimators=n_estimators,
        random_state=RANDOM_STATE,
        class_weight='balanced',  # Handle imbalanced classes
        n_jobs=-1  # Use all CPU cores
    )
    model.fit(X_train, y_train)
    print(f"  Trained with {n_estimators} trees")
    
    # Step 6: Evaluate
    print("\n[Step 6] Evaluating model...")
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    
    print(f"\n  Overall Accuracy: {accuracy:.4f} ({accuracy*100:.2f}%)")
    
    # Classification report - only include labels present in test set
    print("\n  Classification Report:")
    unique_labels = sorted(set(y_test) | set(y_pred))
    target_names = [label_encoder.classes_[i] for i in unique_labels]
    report = classification_report(
        y_test, y_pred,
        labels=unique_labels,
        target_names=target_names,
        zero_division=0
    )
    print(report)
    
    # Confusion matrix
    print("  Confusion Matrix:")
    cm = confusion_matrix(y_test, y_pred, labels=unique_labels)
    print(f"  Labels: {target_names}")
    print(f"  {cm}")
    
    # Feature importance
    print("\n  Feature Importance (Top 10):")
    importance = pd.DataFrame({
        'feature': feature_columns,
        'importance': model.feature_importances_
    }).sort_values('importance', ascending=False)
    
    for idx, row in importance.head(10).iterrows():
        print(f"    {row['feature']:25s} {row['importance']:.4f}")
    
    return model, label_encoder, accuracy, X_test, y_test


def save_model(model, label_encoder, model_path=MODEL_PATH, encoder_path=LABEL_ENCODER_PATH):
    """Save trained model and label encoder to disk."""
    os.makedirs(os.path.dirname(model_path), exist_ok=True)
    
    joblib.dump(model, model_path)
    joblib.dump(label_encoder, encoder_path)
    
    print(f"\n[OK] Model saved to: {model_path}")
    print(f"[OK] Label encoder saved to: {encoder_path}")


def main(data_path: str = DATA_PATH):
    """Main training pipeline."""
    print("\n" + "=" * 70)
    print("MULTI-ATTACK HONEYPOT ML TRAINING PIPELINE")
    print("=" * 70)
    
    try:
        # Load data
        df = load_data(data_path)
        
        # Check minimum samples
        if len(df) < 50:
            print(f"\n[WARNING] Only {len(df)} samples. Recommend at least 100 for reliable training.")
            print("          Run attack simulators to generate more data.")
        
        # Train model
        model, label_encoder, accuracy, X_test, y_test = train_multi_attack_model(df)
        
        # Save if accuracy is reasonable
        if accuracy >= 0.5:
            save_model(model, label_encoder)
            print(f"\n{'='*70}")
            print("TRAINING COMPLETE!")
            print(f"{'='*70}")
            print(f"Accuracy: {accuracy*100:.2f}%")
            print(f"Classes: {len(label_encoder.classes_)}")
            print("Model ready for use in attack_classifier_multi.py")
        else:
            print(f"\n[WARNING] Accuracy too low ({accuracy:.2f}). Not saving model.")
            print("          Need more training data or better feature engineering.")
    
    except FileNotFoundError as e:
        print(f"\n[ERROR] {e}")
        print("\nTo generate training data:")
        print("  1. Start the honeypot manager: python honeypot_manager.py")
        print("  2. Run attack simulators:")
        print("     - python attack_simulator.py")
        print("     - python attack_simulator_portscan.py")
        print("     - python attack_simulator_dns.py")
        print("  3. Re-run this training script")
        sys.exit(1)
    
    except Exception as e:
        print(f"\n[ERROR] Training failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train multi-attack model")
    parser.add_argument(
        "--data",
        default=DATA_PATH,
        help="Path to attack CSV dataset (default: data/attack_logs.csv)",
    )
    args = parser.parse_args()
    main(data_path=args.data)
