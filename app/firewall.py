"""
Firewall Management Module for NeuralShield
Handles automated blocking of malicious IPs
"""

import subprocess
import platform
import logging
from datetime import datetime, timedelta
from config import AUTO_BLOCK_ENABLED, BLOCK_DURATION, WHITELISTED_IPS
from app.database import FirewallRule, db_session

logger = logging.getLogger(__name__)


class FirewallManager:
    """Manages firewall rules for blocking malicious IPs"""
    
    def __init__(self):
        self.system = platform.system()
        self.blocked_ips = set()
        
    def is_linux(self):
        """Check if running on Linux"""
        return self.system == "Linux"
    
    def is_whitelisted(self, ip_address):
        """Check if IP is whitelisted"""
        return ip_address in WHITELISTED_IPS
    
    def block_ip(self, ip_address, reason="Automated threat blocking", duration=None):
        """Block an IP address using iptables"""
        if self.is_whitelisted(ip_address):
            logger.info(f"Skipping blocked for whitelisted IP: {ip_address}")
            return False
            
        if ip_address in self.blocked_ips:
            logger.info(f"IP {ip_address} already blocked")
            return False
            
        if not self.is_linux():
            logger.warning(f"IP blocking not supported on {self.system}. Simulation mode only.")
            self.blocked_ips.add(ip_address)
            self._log_firewall_rule(ip_address, "automatic", reason, duration)
            return True
            
        try:
            result = subprocess.run(
                ["which", "iptables"],
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0:
                logger.error("iptables not found. Install iptables or run as root.")
                return False
                
            check_result = subprocess.run(
                ["iptables", "-L", "INPUT", "-n"],
                capture_output=True,
                text=True
            )
            
            if ip_address in check_result.stdout:
                logger.info(f"IP {ip_address} already in iptables rules")
                return False
            
            cmd = ["iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                self.blocked_ips.add(ip_address)
                duration = duration or BLOCK_DURATION
                expires_at = datetime.utcnow() + timedelta(seconds=duration)
                self._log_firewall_rule(ip_address, "automatic", reason, expires_at)
                logger.info(f"Successfully blocked IP: {ip_address}")
                return True
            else:
                logger.error(f"Failed to block IP {ip_address}: {result.stderr}")
                return False
                
        except Exception as e:
            logger.error(f"Error blocking IP {ip_address}: {e}")
            return False
    
    def unblock_ip(self, ip_address):
        """Unblock an IP address"""
        if not self.is_linux():
            self.blocked_ips.discard(ip_address)
            self._update_firewall_rule(ip_address, active=False)
            logger.info(f"[Simulation] Unblocked IP: {ip_address}")
            return True
            
        try:
            cmd = ["iptables", "-D", "INPUT", "-s", ip_address, "-j", "DROP"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                self.blocked_ips.discard(ip_address)
                self._update_firewall_rule(ip_address, active=False)
                logger.info(f"Successfully unblocked IP: {ip_address}")
                return True
            else:
                logger.error(f"Failed to unblock IP {ip_address}: {result.stderr}")
                return False
                
        except Exception as e:
            logger.error(f"Error unblocking IP {ip_address}: {e}")
            return False
    
    def get_blocked_ips(self):
        """Get list of currently blocked IPs"""
        if not self.is_linux():
            return list(self.blocked_ips)
            
        try:
            result = subprocess.run(
                ["iptables", "-L", "INPUT", "-n", "--line-numbers"],
                capture_output=True,
                text=True
            )
            
            blocked = []
            for line in result.stdout.split('\n'):
                if 'DROP' in line:
                    try:
                        parts = line.split()
                        if len(parts) >= 3:
                            ip = parts[2]
                            if ip != '0.0.0.0/0':
                                blocked.append(ip)
                    except:
                        pass
                        
            return blocked
            
        except Exception as e:
            logger.error(f"Error getting blocked IPs: {e}")
            return list(self.blocked_ips)
    
    def block_ip_range(self, cidr, reason="Automated threat blocking"):
        """Block an IP range using CIDR notation"""
        if not self.is_linux():
            logger.warning("IP range blocking only supported on Linux")
            return False
            
        try:
            cmd = ["iptables", "-A", "INPUT", "-s", cidr, "-j", "DROP"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                logger.info(f"Blocked IP range: {cidr}")
                return True
            else:
                logger.error(f"Failed to block IP range {cidr}: {result.stderr}")
                return False
                
        except Exception as e:
            logger.error(f"Error blocking IP range {cidr}: {e}")
            return False
    
    def _log_firewall_rule(self, ip_address, rule_type, reason, expires_at=None):
        """Log firewall rule to database"""
        try:
            db = db_session()
            rule = FirewallRule(
                ip_address=ip_address,
                rule_type=rule_type,
                reason=reason,
                expires_at=expires_at
            )
            db.add(rule)
            db.commit()
            db.close()
        except Exception as e:
            logger.error(f"Error logging firewall rule: {e}")
    
    def _update_firewall_rule(self, ip_address, active=False):
        """Update firewall rule in database"""
        try:
            db = db_session()
            rule = db.query(FirewallRule).filter(
                FirewallRule.ip_address == ip_address
            ).first()
            if rule:
                rule.active = active
                db.commit()
            db.close()
        except Exception as e:
            logger.error(f"Error updating firewall rule: {e}")
    
    def cleanup_expired_rules(self):
        """Remove expired firewall rules"""
        try:
            db = db_session()
            expired_rules = db.query(FirewallRule).filter(
                FirewallRule.expires_at < datetime.utcnow(),
                FirewallRule.active == True
            ).all()
            
            for rule in expired_rules:
                self.unblock_ip(rule.ip_address)
                
            db.close()
            logger.info(f"Cleaned up {len(expired_rules)} expired rules")
            
        except Exception as e:
            logger.error(f"Error cleaning up expired rules: {e}")
    
    def get_firewall_status(self):
        """Get current firewall status"""
        return {
            "system": self.system,
            "supported": self.is_linux(),
            "blocked_count": len(self.blocked_ips),
            "auto_block_enabled": AUTO_BLOCK_ENABLED,
            "blocked_ips": list(self.blocked_ips)
        }
