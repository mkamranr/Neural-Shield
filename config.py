"""
NeuralShield Configuration Settings
AI-Driven Cyber Defense System
"""

import os
from pathlib import Path

# Base Directory
BASE_DIR = Path(__file__).resolve().parent

# Database Configuration
DATABASE_URL = f"sqlite:///{BASE_DIR / 'data' / 'neuralshield.db'}"

# Model Configuration
MODEL_PATH = BASE_DIR / "models" / "random_forest.pkl"

# Network Configuration
DEFAULT_INTERFACE = "eth0"
SNIFF_FILTER = ""
PACKET_BUFFER_SIZE = 1000

# Detection Thresholds
ANOMALY_THRESHOLD = 0.70
MIN_PACKETS_FOR_ANALYSIS = 5
RATE_LIMIT_THRESHOLD = 100

# Firewall Configuration
AUTO_BLOCK_ENABLED = False
BLOCK_DURATION = 3600
WHITELISTED_IPS = ["127.0.0.1", "192.168.1.1", "10.0.0.1"]

# Attack Signatures
ATTACK_SIGNATURES = {
    "sql_injection": [
        "UNION SELECT", "OR 1=1", "' OR '1'='1", "--", "DROP TABLE",
        "INSERT INTO", "UPDATE SET", "DELETE FROM", "xp_cmdshell"
    ],
    "xss": [
        "<script>", "javascript:", "onload=", "onerror=", "onmouseover=",
        "<iframe>", "<object>", "<embed>", "alert(", "document.cookie"
    ],
    "path_traversal": [
        "../", "..\\", "/etc/passwd", "boot.ini", "win.ini",
        "config.sys", ".env", ".htaccess", "/proc/self/", "../../.."
    ],
    "command_injection": [
        "; rm", "| rm", "&& rm", "`rm`", "wget ", "curl ",
        "nc -e", "/bin/sh", "cmd.exe", "powershell"
    ]
}

# Logging Configuration
LOG_LEVEL = "INFO"
LOG_FILE = BASE_DIR / "logs" / "neuralshield.log"

# Web Server Configuration
HOST = "0.0.0.0"
PORT = 8000
DEBUG = False

# Session Configuration
SECRET_KEY = os.urandom(32).hex()
ACCESS_TOKEN_EXPIRE_MINUTES = 60
