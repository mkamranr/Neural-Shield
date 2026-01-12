"""
AI-Based Threat Detection Engine for NeuralShield
Uses Machine Learning for anomaly detection
"""

import numpy as np
import pandas as pd
from collections import defaultdict
from config import MODEL_PATH, ANOMALY_THRESHOLD
import logging

logger = logging.getLogger(__name__)


class PacketFeatureExtractor:
    """Extract features from network packets for ML analysis"""
    
    def __init__(self):
        self.packet_buffer = defaultdict(list)
        self.window_size = 10
        
    def extract_features(self, packet):
        """Extract features from a single packet"""
        try:
            features = {}
            
            if packet.haslayer('IP'):
                features['packet_length'] = len(packet)
                features['has_tcp'] = 1 if packet.haslayer('TCP') else 0
                features['has_udp'] = 1 if packet.haslayer('UDP') else 0
                features['has_icmp'] = 1 if packet.haslayer('ICMP') else 0
                
                ip_layer = packet['IP']
                features['ip_ttl'] = ip_layer.ttl
                features['ip_flags_df'] = 1 if ip_layer.flags == 'DF' else 0
                features['ip_flags_mf'] = 1 if ip_layer.flags == 'MF' else 0
                
                if packet.haslayer('TCP'):
                    tcp_layer = packet['TCP']
                    features['tcp_flags_syn'] = 1 if tcp_layer.flags.SYN else 0
                    features['tcp_flags_ack'] = 1 if tcp_layer.flags.ACK else 0
                    features['tcp_flags_fin'] = 1 if tcp_layer.flags.FIN else 0
                    features['tcp_flags_rst'] = 1 if tcp_layer.flags.RST else 0
                    features['tcp_flags_psh'] = 1 if tcp_layer.flags.PSH else 0
                    features['tcp_flags_urg'] = 1 if tcp_layer.flags.URG else 0
                    features['tcp_window'] = tcp_layer.window
                    features['tcp_sport'] = tcp_layer.sport
                    features['tcp_dport'] = tcp_layer.dport
                else:
                    features['tcp_window'] = 0
                    features['tcp_sport'] = 0
                    features['tcp_dport'] = 0
                    
                if packet.haslayer('UDP'):
                    udp_layer = packet['UDP']
                    features['udp_sport'] = udp_layer.sport
                    features['udp_dport'] = udp_layer.dport
                    features['udp_length'] = udp_layer.len
                else:
                    features['udp_sport'] = 0
                    features['udp_dport'] = 0
                    features['udp_length'] = 0
                    
                if packet.haslayer('ICMP'):
                    icmp_layer = packet['ICMP']
                    features['icmp_type'] = icmp_layer.type
                    features['icmp_code'] = icmp_layer.code
                else:
                    features['icmp_type'] = 0
                    features['icmp_code'] = 0
                    
                if packet.haslayer('Raw'):
                    payload = packet['Raw'].load
                    features['payload_size'] = len(payload)
                    features['has_null_bytes'] = 1 if b'\x00' in payload else 0
                    features['has_high_entropy'] = self._calculate_entropy(payload) if len(payload) > 0 else 0
                else:
                    features['payload_size'] = 0
                    features['has_null_bytes'] = 0
                    features['has_high_entropy'] = 0
                    
            else:
                features['packet_length'] = len(packet)
                features['has_tcp'] = 0
                features['has_udp'] = 0
                features['has_icmp'] = 0
                features['ip_ttl'] = 64
                features['ip_flags_df'] = 0
                features['ip_flags_mf'] = 0
                features['tcp_window'] = 0
                features['tcp_sport'] = 0
                features['tcp_dport'] = 0
                features['udp_sport'] = 0
                features['udp_dport'] = 0
                features['udp_length'] = 0
                features['icmp_type'] = 0
                features['icmp_code'] = 0
                features['payload_size'] = 0
                features['has_null_bytes'] = 0
                features['has_high_entropy'] = 0
                
            return features
            
        except Exception as e:
            logger.error(f"Error extracting features: {e}")
            return None
    
    def _calculate_entropy(self, data):
        """Calculate entropy of data to detect encryption/compression"""
        if len(data) == 0:
            return 0
        
        entropy = 0
        for x in range(256):
            p_x = float(data.count(x)) / len(data)
            if p_x > 0:
                entropy += - p_x * np.log2(p_x)
        
        return entropy / 8


class ThreatDetector:
    """ML-based threat detection using Random Forest"""
    
    FEATURE_COLUMNS = [
        'packet_length', 'has_tcp', 'has_udp', 'has_icmp',
        'ip_ttl', 'ip_flags_df', 'ip_flags_mf',
        'tcp_window', 'tcp_flags_syn', 'tcp_flags_ack', 'tcp_flags_fin',
        'tcp_flags_rst', 'tcp_flags_psh', 'tcp_flags_urg',
        'udp_length', 'icmp_type', 'icmp_code',
        'payload_size', 'has_null_bytes', 'has_high_entropy'
    ]
    
    def __init__(self):
        self.model = None
        self.feature_extractor = PacketFeatureExtractor()
        self.threat_counts = defaultdict(int)
        self.load_model()
        
    def load_model(self):
        """Load the trained ML model"""
        try:
            if MODEL_PATH.exists():
                import joblib
                self.model = joblib.load(MODEL_PATH)
                logger.info(f"ML model loaded from {MODEL_PATH}")
            else:
                logger.warning(f"Model file not found at {MODEL_PATH}. Using signature-based detection only.")
                self.model = None
        except Exception as e:
            logger.error(f"Error loading model: {e}")
            self.model = None
            
    def detect_signature_based(self, packet):
        """Perform signature-based detection for known attack patterns"""
        from config import ATTACK_SIGNATURES
        
        threats = []
        
        try:
            if packet.haslayer('Raw'):
                payload = packet['Raw'].load.decode('utf-8', errors='ignore').upper()
                
                for attack_type, patterns in ATTACK_SIGNATURES.items():
                    for pattern in patterns:
                        if pattern.upper() in payload:
                            threats.append({
                                'type': attack_type,
                                'confidence': 1.0,
                                'severity': 'HIGH',
                                'details': f"Signature match: {pattern}"
                            })
                            
        except Exception as e:
            logger.error(f"Error in signature detection: {e}")
            
        return threats
    
    def detect_anomaly_based(self, features):
        """Perform ML-based anomaly detection"""
        if self.model is None:
            return []
            
        try:
            df = pd.DataFrame([features], columns=self.FEATURE_COLUMNS)
            
            for col in self.FEATURE_COLUMNS:
                if col not in df.columns:
                    df[col] = 0
            
            prediction = self.model.predict(df)
            probability = self.model.predict_proba(df)
            
            threats = []
            if prediction[0] == 1:
                confidence = probability[0][1]
                if confidence >= ANOMALY_THRESHOLD:
                    threats.append({
                        'type': 'ANOMALY',
                        'confidence': confidence,
                        'severity': 'MEDIUM' if confidence < 0.9 else 'HIGH',
                        'details': f"ML anomaly detection with {confidence:.2%} confidence"
                    })
                    
            return threats
            
        except Exception as e:
            logger.error(f"Error in anomaly detection: {e}")
            return []
    
    def analyze_packet(self, packet, ip_address=None):
        """Complete packet analysis combining signature and ML detection"""
        threats = []
        
        features = self.feature_extractor.extract_features(packet)
        if features is None:
            return threats
            
        if ip_address is None and packet.haslayer('IP'):
            ip_address = packet['IP'].src
            
        signature_threats = self.detect_signature_based(packet)
        threats.extend(signature_threats)
        
        ml_threats = self.detect_anomaly_based(features)
        threats.extend(ml_threats)
        
        if ip_address:
            self.threat_counts[ip_address] += len(threats)
            
        return threats
    
    def check_rate_based(self, ip_address, current_time):
        """Check for rate-based attacks (DoS/DDoS)"""
        threats = []
        
        if self.threat_counts[ip_address] > 10:
            threats.append({
                'type': 'RATE_BASED',
                'confidence': 0.95,
                'severity': 'CRITICAL',
                'details': f"High threat rate detected: {self.threat_counts[ip_address]} threats"
            })
            
        return threats
    
    def get_threat_severity(self, threat_type, confidence):
        """Determine threat severity based on type and confidence"""
        severity_map = {
            'sql_injection': 'HIGH',
            'xss': 'MEDIUM',
            'path_traversal': 'HIGH',
            'command_injection': 'CRITICAL',
            'ANOMALY': 'MEDIUM' if confidence < 0.9 else 'HIGH',
            'RATE_BASED': 'CRITICAL'
        }
        
        return severity_map.get(threat_type, 'MEDIUM')
