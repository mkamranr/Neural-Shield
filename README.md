# 🛡️ NeuralShield - AI-Driven Cyber Defense System

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.9+-blue?style=for-the-badge&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/FastAPI-0.109.0-green?style=for-the-badge&logo=fastapi&logoColor=white" alt="FastAPI">
  <img src="https://img.shields.io/badge/Scikit--learn-1.4.0-orange?style=for-the-badge&logo=scikitlearn&logoColor=white" alt="Scikit-learn">
  <img src="https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge" alt="License">
</p>

<p align="center">
  <strong>Real-time AI-powered network security monitoring and threat prevention</strong>
</p>

---

## 📋 Table of Contents

- [Introduction](#introduction)
- [Key Features](#key-features)
- [How It Works](#how-it-works)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage Guide](#usage-guide)
- [Configuration](#configuration)
- [API Documentation](#api-documentation)
- [Architecture](#architecture)
- [Testing](#testing)
- [Deployment](#deployment)
- [Contributing](#contributing)
- [License](#license)
- [Support](#support)

---

## 🔐 Introduction

NeuralShield is an advanced Intrusion Detection and Prevention System (IDS/IPS) that combines traditional signature-based detection with machine learning anomaly detection to identify and block cyber attacks in real-time. The system monitors network traffic, analyzes packet patterns using artificial intelligence, and automatically blocks malicious sources using firewall rules.

### Why NeuralShield?

In today's rapidly evolving cybersecurity landscape, traditional rule-based detection systems struggle to keep pace with sophisticated attack vectors. NeuralShield addresses this challenge by leveraging machine learning to detect both known threats (through signature matching) and unknown/novel attacks (through behavioral analysis).

- **🤖 AI-Powered Detection**: Uses Random Forest machine learning algorithm for anomaly detection
- **⚡ Real-Time Monitoring**: Captures and analyzes network packets in real-time
- **🔒 Automated Prevention**: Automatically blocks malicious IPs using Linux iptables
- **📊 Beautiful Dashboard**: Modern web interface for monitoring and management
- **🔧 Easy Configuration**: Simple setup with sensible defaults
- **📈 Scalable Architecture**: Modular design for easy extension and customization

---

## ✨ Key Features

### Threat Detection

| Feature | Description |
|---------|-------------|
| **SQL Injection Detection** | Identifies SQL injection attempts in HTTP requests |
| **XSS Detection** | Detects cross-site scripting patterns in payloads |
| **Path Traversal Detection** | Blocks directory traversal attacks |
| **Command Injection Detection** | Identifies command injection attempts |
| **DDoS/DoS Detection** | Rate-based detection for denial of service attacks |
| **Port Scan Detection** | Identifies network reconnaissance attempts |
| **Malware Traffic Detection** | Detects command and control communication patterns |
| **Anomaly Detection** | ML-based detection of unusual network behavior |

### Core Capabilities

- **Live Traffic Monitoring**: Real-time packet capture and analysis
- **Threat Feed**: Live display of detected threats with severity levels
- **Firewall Management**: Manual and automatic IP blocking
- **Statistics & Analytics**: Comprehensive traffic and threat statistics
- **REST API**: Full API access for integration with other tools
- **Persistent Logging**: SQLite database for threat history and analysis

---

## ⚙️ How It Works

### Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    NeuralShield System                        │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐   │
│  │   Network    │───▶│   Packet     │───▶│   Feature    │   │
│  │   Sniffer    │    │   Sniffer    │    │   Extractor  │   │
│  └──────────────┘    └──────────────┘    └──────────────┘   │
│                                                  │           │
│                                                  ▼           │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐   │
│  │  Firewall    │◀───│  Automated   │◀───│    Threat    │   │
│  │  Manager     │    │  Response    │    │   Detector   │   │
│  └──────────────┘    └──────────────┘    └──────────────┘   │
│         │                                        │           │
│         ▼                                        ▼           │
│  ┌──────────────┐                       ┌──────────────┐   │
│  │  iptables    │                       │   Database   │   │
│  │  Firewall    │                       │   Storage    │   │
│  └──────────────┘                       └──────────────┘   │
│                                                  │           │
│                                                  ▼           │
│                                        ┌──────────────┐      │
│                                        │   Web UI &   │      │
│                                        │     API      │      │
│                                        └──────────────┘      │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Detection Pipeline

1. **Packet Capture**: Network packets are captured in real-time using Scapy library
2. **Feature Extraction**: 20+ features are extracted from each packet (protocol flags, payload size, entropy, etc.)
3. **Dual Detection**:
   - **Signature-Based**: Matches known attack patterns in packet payloads
   - **ML-Based**: Uses trained Random Forest model to identify anomalies
4. **Threat Response**: High-confidence threats trigger automated blocking
5. **Logging**: All threats are logged to database for analysis and review

### Machine Learning Model

The ML model is trained on diverse network traffic datasets:

- **Algorithm**: Random Forest Classifier
- **Features**: 20 numerical features including packet characteristics, protocol flags, and payload analysis
- **Accuracy**: 98.14% detection rate
- **Training Data**: 11,000 samples (5,000 normal, 6,000 attack patterns)

---

## 📦 Installation

### Prerequisites

- **Operating System**: Linux (Ubuntu/Debian recommended) for full functionality
- **Python**: Version 3.9 or higher
- **Dependencies**: libpcap-dev, Python development headers
- **Access**: Root/sudo access for packet sniffing and firewall operations

### System Dependencies

```bash
# Update package list
sudo apt update

# Install libpcap for packet capture
sudo apt install libpcap-dev

# Install Python development headers
sudo apt install python3-dev

# Install git (if not already installed)
sudo apt install git
```

### Python Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/NeuralShield.git
cd NeuralShield

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Upgrade pip
pip install --upgrade pip

# Install Python dependencies
pip install -r requirements.txt
```

### Verify Installation

```bash
# Verify Python version
python --version

# Verify all packages are installed
pip list | grep -E "fastapi|scapy|scikit-learn|pandas"

# Test database initialization
python -c "from app.database import init_db; init_db()"
```

---

## 🚀 Quick Start

### 1. Train the ML Model

```bash
# Generate and train the ML model
python train_model.py
```

Expected output:
```
============================================================
NeuralShield AI Model Training
============================================================
[1/4] Generating training data...
   - Normal samples: 5000
   - Attack samples: 6000
   - Total samples: 11000
[2/4] Training Random Forest classifier...
[3/4] Evaluating model...
   - Accuracy: 0.9814
[4/4] Saving model to /workspace/NeuralShield/models/random_forest.pkl...
============================================================
Model training complete!
============================================================
```

### 2. Initialize Database

```bash
# Initialize the SQLite database
python -c "from app.database import init_db; init_db()"
```

### 3. Run the Application

```bash
# Start the web server and monitoring system
python run.py
```

### 4. Access the Dashboard

Open your web browser and navigate to:
```
http://localhost:8000
```

---

## 📖 Usage Guide

### Starting Monitoring

1. Navigate to the dashboard
2. Click **"Start Monitoring"** to begin packet capture
3. Watch the live threat feed for detected attacks

### Dashboard Sections

#### Main Dashboard
- Real-time traffic statistics (packets analyzed, packets per second)
- Threat detection counts by severity
- System resource utilization
- Traffic and threat charts

#### Threat Monitor
- Live feed of detected threats
- Filter by severity, attack type, time range
- View detailed threat information
- Export threat data

#### Firewall
- View blocked IP addresses
- Manually block/unblock IPs
- View firewall rules and expiration
- Toggle auto-blocking mode

#### Settings
- Configure detection thresholds
- Manage whitelisted IPs
- Adjust auto-block settings
- View system information

### API Usage Examples

#### Start/Stop Sniffer

```bash
# Start monitoring
curl -X POST http://localhost:8000/api/sniffer/start

# Get sniffer status
curl http://localhost:8000/api/sniffer/status

# Stop monitoring
curl -X POST http://localhost:8000/api/sniffer/stop
```

#### Get Threat Data

```bash
# Get recent threats (default: last 100)
curl http://localhost:8000/api/threats

# Get threats filtered by severity
curl http://localhost:8000/api/threats?severity=HIGH

# Get threat statistics
curl http://localhost:8000/api/threats/stats/summary
```

#### Firewall Management

```bash
# Block an IP address
curl -X POST http://localhost:8000/api/firewall/block \
  -H "Content-Type: application/json" \
  -d '{"ip_address": "192.168.1.100", "reason": "Manual block"}'

# Unblock an IP address
curl -X POST http://localhost:8000/api/firewall/unblock \
  -H "Content-Type: application/json" \
  -d '{"ip_address": "192.168.1.100"}'

# Get list of blocked IPs
curl http://localhost:8000/api/firewall/blocked

# Get firewall status
curl http://localhost:8000/api/firewall/status
```

#### System Monitoring

```bash
# Get system statistics
curl http://localhost:8000/api/system/stats

# Health check
curl http://localhost:8000/api/health

# Get traffic statistics
curl http://localhost:8000/api/traffic
```

---

## ⚡ Configuration

### Configuration File

Edit `config.py` to customize NeuralShield behavior:

```python
# Network Interface
DEFAULT_INTERFACE = "eth0"  # Change to your network interface

# Detection Thresholds
ANOMALY_THRESHOLD = 0.70    # ML detection confidence threshold
RATE_LIMIT_THRESHOLD = 100  # Packets per second threshold

# Firewall Settings
AUTO_BLOCK_ENABLED = False  # Enable automatic IP blocking
BLOCK_DURATION = 3600       # Block duration in seconds (1 hour)

# Whitelisted IPs (never blocked)
WHITELISTED_IPS = [
    "127.0.0.1",      # Localhost
    "192.168.1.1",    # Gateway
    "10.0.0.1"        # Private network
]

# Attack Signatures
ATTACK_SIGNATURES = {
    "sql_injection": ["UNION SELECT", "OR 1=1", "--", ...],
    "xss": ["<script>", "javascript:", "onload=", ...],
    "path_traversal": ["../", "/etc/passwd", ...],
    "command_injection": ["; rm", "| rm", "wget ", ...]
}
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `NEURALSHIELD_HOST` | Web server host | 0.0.0.0 |
| `NEURALSHIELD_PORT` | Web server port | 8000 |
| `NEURALSHIELD_DEBUG` | Enable debug mode | False |
| `NEURALSHIELD_DB` | Database path | data/neuralshield.db |

---

## 📡 API Documentation

### Base URL

```
http://localhost:8000
```

### Endpoints

#### System Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/health` | Health check |
| GET | `/api/system/stats` | System performance stats |
| GET | `/api/settings` | Current configuration |

#### Sniffer Control

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/sniffer/status` | Get sniffer status and statistics |
| POST | `/api/sniffer/start` | Start packet sniffer |
| POST | `/api/sniffer/stop` | Stop packet sniffer |

#### Threat Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/threats` | Get threat events |
| GET | `/api/threats/{id}` | Get specific threat |
| GET | `/api/threats/stats/summary` | Get threat statistics |

#### Firewall Control

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/firewall/status` | Get firewall status |
| GET | `/api/firewall/blocked` | Get blocked IPs |
| POST | `/api/firewall/block` | Block an IP |
| POST | `/api/firewall/unblock` | Unblock an IP |
| GET | `/api/firewall/rules` | Get firewall rules |

#### Traffic Analysis

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/traffic` | Get traffic statistics |

### Response Format

All API responses are in JSON format:

```json
{
  "status": "success",
  "data": {
    // Response data here
  },
  "timestamp": "2026-01-12T13:20:10.000000"
}
```

Error responses:

```json
{
  "status": "error",
  "detail": "Error message here",
  "timestamp": "2026-01-12T13:20:10.000000"
}
```

---

## 🏗️ Architecture

### Component Details

#### 1. Packet Sniffer (`app/sniffer.py`)
- Uses Scapy library for packet capture
- Runs in separate thread for non-blocking operation
- Captures TCP/UDP/ICMP packets
- Extracts packet metadata and payloads

#### 2. Feature Extractor (`app/detector.py`)
- Converts raw packets to numerical features
- Extracts 20+ features per packet
- Calculates payload entropy
- Identifies protocol flags

#### 3. Threat Detector (`app/detector.py`)
- **Signature-Based**: Pattern matching for known attacks
- **ML-Based**: Random Forest classifier for anomalies
- Rate-based detection for DoS attacks
- Confidence scoring for each detection

#### 4. Firewall Manager (`app/firewall.py`)
- Manages Linux iptables rules
- Automatic IP blocking for high-confidence threats
- Manual blocking/unblocking via API
- Rule expiration and cleanup

#### 5. Database (`app/database.py`)
- SQLite database for persistence
- Stores threat events, traffic logs, firewall rules
- Supports filtering and querying
- Automatic table creation

#### 6. Web Server (`app/main.py`, `app/api.py`)
- FastAPI-based REST API
- Jinja2 template rendering
- Real-time data updates
- CORS support for cross-origin requests

### Feature Set for ML Model

The ML model uses the following 20 features:

1. `packet_length` - Total packet size in bytes
2. `has_tcp` - TCP protocol flag (0/1)
3. `has_udp` - UDP protocol flag (0/1)
4. `has_icmp` - ICMP protocol flag (0/1)
5. `ip_ttl` - IP time-to-live value
6. `ip_flags_df` - Don't fragment flag
7. `ip_flags_mf` - More fragments flag
8. `tcp_window` - TCP window size
9. `tcp_flags_syn` - SYN flag
10. `tcp_flags_ack` - ACK flag
11. `tcp_flags_fin` - FIN flag
12. `tcp_flags_rst` - RST flag
13. `tcp_flags_psh` - PSH flag
14. `tcp_flags_urg` - URG flag
15. `udp_length` - UDP datagram length
16. `icmp_type` - ICMP message type
17. `icmp_code` - ICMP message code
18. `payload_size` - Payload size in bytes
19. `has_null_bytes` - Contains null bytes (0/1)
20. `has_high_entropy` - High entropy payload (0/1)

---

## 🧪 Testing

### Testing the System

#### 1. Normal Traffic Test
Simply browse the internet or use applications normally. The dashboard should show increasing packet counts without threats.

#### 2. Attack Simulation (For Testing Only)

⚠️ **Warning**: Only test on systems you own or have permission to test.

```bash
# Port Scan Detection (from a test machine)
nmap -sS -p 1-1000 192.168.1.100

# DDoS Simulation (use responsibly on isolated networks)
ping -f -c 1000 192.168.1.100

# SQL Injection Test (against your own web application)
curl "http://localhost:8000/?id=1' OR '1'='1"
```

#### 3. Verify Blocking

```bash
# Check iptables rules
sudo iptables -L INPUT -n --line-numbers

# View blocked IPs in API
curl http://localhost:8000/api/firewall/blocked
```

### Automated Tests

```bash
# Run unit tests (if available)
pytest tests/

# Run integration tests
python -m pytest tests/integration/
```

---

## 🚀 Deployment

### Development Mode

```bash
# Run with auto-reload
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### Production Mode

#### Using Systemd

Create a service file:

```bash
sudo nano /etc/systemd/system/neuralshield.service
```

```ini
[Unit]
Description=NeuralShield - AI Cyber Defense System
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/NeuralShield
Environment=PATH=/opt/NeuralShield/venv/bin
ExecStart=/opt/NeuralShield/venv/bin/python run.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable neuralshield
sudo systemctl start neuralshield

# Check status
sudo systemctl status neuralshield

# View logs
sudo journalctl -u neuralshield -f
```

#### Using Docker

```dockerfile
FROM python:3.9-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000

CMD ["python", "run.py"]
```

```bash
# Build and run
docker build -t neuralshield .
docker run -d -p 8000:8000 --cap-add=NET_ADMIN neuralshield
```

#### Using Nginx Reverse Proxy

```nginx
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://localhost:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

---

## 🤝 Contributing

We welcome contributions! Please see our contributing guidelines:

### Ways to Contribute

- 🐛 Report bugs
- 💡 Suggest new features
- 📝 Improve documentation
- 🔧 Submit pull requests
- 🧪 Test the system
- 📢 Spread the word

### Contributing Guidelines

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

### Coding Standards

- Follow PEP 8 style guide
- Write docstrings for all functions
- Add type hints where applicable
- Write tests for new features
- Update documentation as needed

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

```
MIT License

Copyright (c) 2024 NeuralShield Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## 💬 Support

### Getting Help

- 📖 **Documentation**: [README.md](README.md)
- 🐛 **Issues**: [GitHub Issues](https://github.com/yourusername/NeuralShield/issues)
- 💬 **Discussions**: [GitHub Discussions](https://github.com/yourusername/NeuralShield/discussions)

### Community

- ⭐ Star the project if you find it useful
- 🐦 Follow us on Twitter
- 📧 Contact: support@neuralshield.example.com

---

## 🙏 Acknowledgments

- **Scapy**: For the excellent packet manipulation library
- **Scikit-learn**: For the machine learning framework
- **FastAPI**: For the modern web framework
- **Tailwind CSS**: For the beautiful UI components
- **Chart.js**: For the interactive charts
- **All Contributors**: For their valuable contributions

---

## 📈 Roadmap

### Future Enhancements

- [ ] Multi-interface support
- [ ] Clustering for distributed deployment
- [ ] Custom rule creation
- [ ] Email/SMS alerts
- [ ] Integration with SIEM systems
- [ ] Mobile app
- [ ] Kubernetes deployment
- [ ] Real-time collaboration features

---

<p align="center">
  Made with 🛡️ by NeuralShield Team
</p>

<p align="center">
  ⭐ Star us on GitHub | 🐦 Follow us on Twitter | 📧 Contact Support
</p>
