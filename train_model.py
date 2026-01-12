"""
NeuralShield Model Training Script
Generates initial ML model for threat detection
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import joblib
from datetime import datetime, timedelta
from random import randint, choice
import os

from config import MODEL_PATH

NORMAL_SAMPLES = 5000
ATTACK_SAMPLES = 3000


def generate_normal_traffic():
    """Generate normal traffic samples"""
    data = []
    
    for _ in range(NORMAL_SAMPLES):
        sample = {
            'packet_length': randint(64, 1500),
            'has_tcp': 1,
            'has_udp': 0,
            'has_icmp': 0,
            'ip_ttl': randint(32, 128),
            'ip_flags_df': randint(0, 1),
            'ip_flags_mf': 0,
            'tcp_window': randint(1024, 65535),
            'tcp_flags_syn': 0,
            'tcp_flags_ack': 1,
            'tcp_flags_fin': 0,
            'tcp_flags_rst': 0,
            'tcp_flags_psh': 1,
            'tcp_flags_urg': 0,
            'udp_length': 0,
            'icmp_type': 0,
            'icmp_code': 0,
            'payload_size': randint(0, 1000),
            'has_null_bytes': 0,
            'has_high_entropy': randint(0, 1)
        }
        data.append(sample)
        
    return data


def generate_ddos_traffic():
    """Generate DDoS/DoS attack samples"""
    data = []
    
    for _ in range(ATTACK_SAMPLES // 3):
        sample = {
            'packet_length': randint(40, 64),
            'has_tcp': 1,
            'has_udp': 0,
            'has_icmp': 0,
            'ip_ttl': randint(1, 64),
            'ip_flags_df': 0,
            'ip_flags_mf': 0,
            'tcp_window': randint(0, 1024),
            'tcp_flags_syn': 1,
            'tcp_flags_ack': 0,
            'tcp_flags_fin': 0,
            'tcp_flags_rst': 0,
            'tcp_flags_psh': 0,
            'tcp_flags_urg': 0,
            'udp_length': 0,
            'icmp_type': 0,
            'icmp_code': 0,
            'payload_size': 0,
            'has_null_bytes': 0,
            'has_high_entropy': 0
        }
        data.append(sample)
        
        sample = {
            'packet_length': randint(28, 64),
            'has_tcp': 0,
            'has_udp': 0,
            'has_icmp': 1,
            'ip_ttl': randint(1, 64),
            'ip_flags_df': 0,
            'ip_flags_mf': 0,
            'tcp_window': 0,
            'tcp_flags_syn': 0,
            'tcp_flags_ack': 0,
            'tcp_flags_fin': 0,
            'tcp_flags_rst': 0,
            'tcp_flags_psh': 0,
            'tcp_flags_urg': 0,
            'udp_length': 0,
            'icmp_type': 8,
            'icmp_code': 0,
            'payload_size': randint(0, 32),
            'has_null_bytes': 0,
            'has_high_entropy': 0
        }
        data.append(sample)
        
        sample = {
            'packet_length': randint(28, 1500),
            'has_tcp': 0,
            'has_udp': 1,
            'has_icmp': 0,
            'ip_ttl': randint(1, 64),
            'ip_flags_df': 0,
            'ip_flags_mf': 0,
            'tcp_window': 0,
            'tcp_flags_syn': 0,
            'tcp_flags_ack': 0,
            'tcp_flags_fin': 0,
            'tcp_flags_rst': 0,
            'tcp_flags_psh': 0,
            'tcp_flags_urg': 0,
            'udp_length': randint(100, 1500),
            'icmp_type': 0,
            'icmp_code': 0,
            'payload_size': randint(100, 1500),
            'has_null_bytes': randint(0, 1),
            'has_high_entropy': randint(0, 1)
        }
        data.append(sample)
        
    return data


def generate_malware_traffic():
    """Generate malware/C&C traffic samples"""
    data = []
    
    for _ in range(ATTACK_SAMPLES // 3):
        sample = {
            'packet_length': randint(40, 1500),
            'has_tcp': 1,
            'has_udp': 0,
            'has_icmp': 0,
            'ip_ttl': randint(1, 128),
            'ip_flags_df': randint(0, 1),
            'ip_flags_mf': 0,
            'tcp_window': randint(0, 65535),
            'tcp_flags_syn': 0,
            'tcp_flags_ack': 1,
            'tcp_flags_fin': randint(0, 1),
            'tcp_flags_rst': 0,
            'tcp_flags_psh': 1,
            'tcp_flags_urg': 0,
            'udp_length': 0,
            'icmp_type': 0,
            'icmp_code': 0,
            'payload_size': randint(0, 500),
            'has_null_bytes': randint(0, 1),
            'has_high_entropy': 1
        }
        data.append(sample)
        
        sample = {
            'packet_length': randint(40, 100),
            'has_tcp': 1,
            'has_udp': 0,
            'has_icmp': 0,
            'ip_ttl': randint(64, 128),
            'ip_flags_df': 0,
            'ip_flags_mf': 0,
            'tcp_window': randint(0, 1024),
            'tcp_flags_syn': 0,
            'tcp_flags_ack': 0,
            'tcp_flags_fin': 1,
            'tcp_flags_rst': 1,
            'tcp_flags_psh': 0,
            'tcp_flags_urg': 0,
            'udp_length': 0,
            'icmp_type': 0,
            'icmp_code': 0,
            'payload_size': 0,
            'has_null_bytes': 0,
            'has_high_entropy': 0
        }
        data.append(sample)
        
    return data


def generate_port_scan_traffic():
    """Generate port scan traffic samples"""
    data = []
    
    for _ in range(ATTACK_SAMPLES // 3):
        sample = {
            'packet_length': 40,
            'has_tcp': 1,
            'has_udp': 0,
            'has_icmp': 0,
            'ip_ttl': randint(1, 128),
            'ip_flags_df': 0,
            'ip_flags_mf': 0,
            'tcp_window': randint(0, 1024),
            'tcp_flags_syn': 1,
            'tcp_flags_ack': 0,
            'tcp_flags_fin': 0,
            'tcp_flags_rst': 0,
            'tcp_flags_psh': 0,
            'tcp_flags_urg': 0,
            'udp_length': 0,
            'icmp_type': 0,
            'icmp_code': 0,
            'payload_size': 0,
            'has_null_bytes': 0,
            'has_high_entropy': 0
        }
        data.append(sample)
        
    return data


def train_model():
    """Main training function"""
    print("=" * 60)
    print("NeuralShield AI Model Training")
    print("=" * 60)
    
    print("\n[1/4] Generating training data...")
    
    normal_data = generate_normal_traffic()
    attack_data = (
        generate_ddos_traffic() + 
        generate_malware_traffic() + 
        generate_port_scan_traffic()
    )
    
    all_data = normal_data + attack_data
    labels = [0] * len(normal_data) + [1] * len(attack_data)
    
    df = pd.DataFrame(all_data)
    df['label'] = labels
    
    print(f"   - Normal samples: {len(normal_data)}")
    print(f"   - Attack samples: {len(attack_data)}")
    print(f"   - Total samples: {len(df)}")
    
    X = df.drop('label', axis=1)
    y = df['label']
    
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    print(f"\n[2/4] Training Random Forest classifier...")
    
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        min_samples_split=5,
        min_samples_leaf=2,
        random_state=42,
        n_jobs=-1
    )
    
    model.fit(X_train, y_train)
    
    print(f"\n[3/4] Evaluating model...")
    y_pred = model.predict(X_test)
    
    accuracy = accuracy_score(y_test, y_pred)
    print(f"   - Accuracy: {accuracy:.4f}")
    
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=['Normal', 'Malicious']))
    
    print("\nTop 10 Feature Importances:")
    importance_df = pd.DataFrame({
        'feature': X.columns,
        'importance': model.feature_importances_
    }).sort_values('importance', ascending=False)
    
    for idx, row in importance_df.head(10).iterrows():
        print(f"   - {row['feature']}: {row['importance']:.4f}")
    
    print(f"\n[4/4] Saving model to {MODEL_PATH}...")
    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    
    print("\n" + "=" * 60)
    print("Model training complete!")
    print(f"Model saved to: {MODEL_PATH}")
    print("=" * 60)
    
    return model


if __name__ == "__main__":
    train_model()
