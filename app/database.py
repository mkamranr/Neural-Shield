"""
Database Models and Operations for NeuralShield
"""

from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Boolean, Text, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, scoped_session
from datetime import datetime
from config import DATABASE_URL

Base = declarative_base()
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
db_session = scoped_session(SessionLocal)


class ThreatEvent(Base):
    """Model for storing detected threat events"""
    __tablename__ = "threat_events"
    
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    source_ip = Column(String(45), index=True)
    destination_ip = Column(String(45))
    source_port = Column(Integer)
    destination_port = Column(Integer)
    protocol = Column(String(10))
    attack_type = Column(String(50), index=True)
    confidence = Column(Float)
    severity = Column(String(20), index=True)
    raw_packet = Column(Text)
    action_taken = Column(String(50))
    blocked = Column(Boolean, default=False)
    extra_data = Column(JSON)
    
    def to_dict(self):
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "source_port": self.source_port,
            "destination_port": self.destination_port,
            "protocol": self.protocol,
            "attack_type": self.attack_type,
            "confidence": self.confidence,
            "severity": self.severity,
            "action_taken": self.action_taken,
            "blocked": self.blocked,
            "metadata": self.extra_data
        }


class TrafficLog(Base):
    """Model for storing traffic statistics"""
    __tablename__ = "traffic_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    total_packets = Column(Integer)
    tcp_packets = Column(Integer)
    udp_packets = Column(Integer)
    icmp_packets = Column(Integer)
    unique_sources = Column(Integer)
    unique_destinations = Column(Integer)
    blocked_count = Column(Integer)
    threat_count = Column(Integer)
    
    def to_dict(self):
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "total_packets": self.total_packets,
            "tcp_packets": self.tcp_packets,
            "udp_packets": self.udp_packets,
            "icmp_packets": self.icmp_packets,
            "unique_sources": self.unique_sources,
            "unique_destinations": self.unique_destinations,
            "blocked_count": self.blocked_count,
            "threat_count": self.threat_count
        }


class FirewallRule(Base):
    """Model for firewall rules"""
    __tablename__ = "firewall_rules"
    
    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String(45), unique=True, index=True)
    rule_type = Column(String(20))
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime)
    active = Column(Boolean, default=True)
    reason = Column(Text)
    
    def to_dict(self):
        return {
            "id": self.id,
            "ip_address": self.ip_address,
            "rule_type": self.rule_type,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "active": self.active,
            "reason": self.reason
        }


class SystemStats(Base):
    """Model for system statistics"""
    __tablename__ = "system_stats"
    
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    cpu_usage = Column(Float)
    memory_usage = Column(Float)
    packets_analyzed = Column(Integer)
    threats_detected = Column(Integer)
    packets_blocked = Column(Integer)
    model_accuracy = Column(Float)
    
    def to_dict(self):
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "cpu_usage": self.cpu_usage,
            "memory_usage": self.memory_usage,
            "packets_analyzed": self.packets_analyzed,
            "threats_detected": self.threats_detected,
            "packets_blocked": self.packets_blocked,
            "model_accuracy": self.model_accuracy
        }


def init_db():
    """Initialize the database and create tables"""
    Base.metadata.create_all(bind=engine)
    print(f"Database initialized at {DATABASE_URL}")


def get_db():
    """Get database session"""
    db = SessionLocal()
    try:
        return db
    finally:
        pass


def close_db(exception=None):
    """Close database session"""
    db_session.remove()
