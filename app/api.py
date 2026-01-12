"""
REST API Endpoints for NeuralShield
"""

from fastapi import APIRouter, HTTPException
from datetime import datetime, timedelta
from typing import Optional
from app.database import ThreatEvent, TrafficLog, FirewallRule, db_session
from app.sniffer import PacketSniffer
from app.firewall import FirewallManager

router = APIRouter()
firewall = FirewallManager()


def get_sniffer():
    """Get or create packet sniffer instance"""
    global sniffer
    if 'sniffer' not in globals() or sniffer is None:
        sniffer = PacketSniffer()
    return sniffer


sniffer = None


@router.get("/api/threats")
async def get_threats(limit: int = 100, severity: Optional[str] = None):
    """Get threat events with optional filtering"""
    try:
        db = db_session()
        query = db.query(ThreatEvent).order_by(ThreatEvent.timestamp.desc())
        
        if severity:
            query = query.filter(ThreatEvent.severity == severity)
            
        threats = query.limit(limit).all()
        result = [t.to_dict() for t in threats]
        db.close()
        return {"threats": result, "count": len(result)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/threats/{threat_id}")
async def get_threat(threat_id: int):
    """Get a specific threat event"""
    try:
        db = db_session()
        threat = db.query(ThreatEvent).filter(ThreatEvent.id == threat_id).first()
        
        if not threat:
            raise HTTPException(status_code=404, detail="Threat not found")
            
        result = threat.to_dict()
        db.close()
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/threats/stats/summary")
async def get_threat_stats():
    """Get threat statistics summary"""
    try:
        db = db_session()
        
        high_count = db.query(ThreatEvent).filter(ThreatEvent.severity == 'HIGH').count()
        critical_count = db.query(ThreatEvent).filter(ThreatEvent.severity == 'CRITICAL').count()
        medium_count = db.query(ThreatEvent).filter(ThreatEvent.severity == 'MEDIUM').count()
        
        attack_types = db.query(
            ThreatEvent.attack_type, 
            db.func.count(ThreatEvent.id)
        ).group_by(ThreatEvent.attack_type).all()
        
        hour_ago = datetime.utcnow() - timedelta(hours=1)
        recent_threats = db.query(ThreatEvent).filter(
            ThreatEvent.timestamp > hour_ago
        ).count()
        
        db.close()
        
        return {
            "by_severity": {
                "high": high_count,
                "critical": critical_count,
                "medium": medium_count
            },
            "by_type": dict(attack_types),
            "last_hour": recent_threats,
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/firewall/status")
async def get_firewall_status():
    """Get current firewall status"""
    return firewall.get_firewall_status()


@router.get("/api/firewall/blocked")
async def get_blocked_ips():
    """Get list of blocked IPs"""
    return {"blocked_ips": firewall.get_blocked_ips()}


@router.post("/api/firewall/block")
async def block_ip(request: dict):
    """Manually block an IP address"""
    ip_address = request.get("ip_address")
    reason = request.get("reason", "Manual blocking")
    duration = request.get("duration", 3600)
    
    if not ip_address:
        raise HTTPException(status_code=400, detail="IP address required")
    
    success = firewall.block_ip(ip_address, reason, duration)
    return {"success": success, "ip_address": ip_address}


@router.post("/api/firewall/unblock")
async def unblock_ip(request: dict):
    """Unblock an IP address"""
    ip_address = request.get("ip_address")
    
    if not ip_address:
        raise HTTPException(status_code=400, detail="IP address required")
    
    success = firewall.unblock_ip(ip_address)
    return {"success": success, "ip_address": ip_address}


@router.get("/api/firewall/rules")
async def get_firewall_rules():
    """Get firewall rules from database"""
    try:
        db = db_session()
        rules = db.query(FirewallRule).filter(FirewallRule.active == True).all()
        result = [r.to_dict() for r in rules]
        db.close()
        return {"rules": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/sniffer/status")
async def get_sniffer_status():
    """Get sniffer status and statistics"""
    global sniffer
    if sniffer is None:
        sniffer = PacketSniffer()
    return sniffer.get_stats()


@router.post("/api/sniffer/start")
async def start_sniffer():
    """Start the packet sniffer"""
    global sniffer
    if sniffer is None:
        sniffer = PacketSniffer()
    if sniffer.running:
        return {"message": "Sniffer already running"}
    
    sniffer.start()
    return {"message": "Sniffer started successfully"}


@router.post("/api/sniffer/stop")
async def stop_sniffer():
    """Stop the packet sniffer"""
    global sniffer
    if sniffer is None:
        return {"message": "Sniffer not running"}
    if not sniffer.running:
        return {"message": "Sniffer not running"}
    
    sniffer.stop()
    return {"message": "Sniffer stopped successfully"}


@router.get("/api/traffic")
async def get_traffic_stats(limit: int = 100):
    """Get traffic statistics"""
    try:
        db = db_session()
        stats = db.query(TrafficLog).order_by(
            TrafficLog.timestamp.desc()
        ).limit(limit).all()
        result = [s.to_dict() for s in stats]
        db.close()
        return {"traffic_stats": result, "count": len(result)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/system/stats")
async def get_system_stats():
    """Get system performance stats"""
    import psutil
    
    return {
        "cpu_percent": psutil.cpu_percent(),
        "memory_percent": psutil.virtual_memory().percent,
        "disk_percent": psutil.disk_usage('/').percent,
        "timestamp": datetime.utcnow().isoformat()
    }


@router.get("/api/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}


@router.get("/api/settings")
async def get_settings():
    """Get current settings"""
    from config import AUTO_BLOCK_ENABLED, ANOMALY_THRESHOLD
    
    return {
        "auto_block_enabled": AUTO_BLOCK_ENABLED,
        "anomaly_threshold": ANOMALY_THRESHOLD,
        "firewall_status": firewall.get_firewall_status()
    }


@router.post("/api/settings/auto-block")
async def toggle_auto_block(request: dict):
    """Toggle auto-blocking feature"""
    global AUTO_BLOCK_ENABLED
    enabled = request.get("enabled", False)
    return {"auto_block_enabled": enabled}
