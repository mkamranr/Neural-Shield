"""
Network Packet Sniffer for NeuralShield
Captures and analyzes network traffic in real-time
"""

from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
from datetime import datetime
from collections import defaultdict
import threading
import logging
from app.detector import ThreatDetector
from app.firewall import FirewallManager
from app.database import ThreatEvent, TrafficLog, db_session
from config import DEFAULT_INTERFACE, AUTO_BLOCK_ENABLED, SNIFF_FILTER

logger = logging.getLogger(__name__)


class PacketSniffer:
    """Real-time network packet sniffer and analyzer"""
    
    def __init__(self, interface=None):
        self.interface = interface or DEFAULT_INTERFACE
        self.detector = ThreatDetector()
        self.firewall = FirewallManager()
        self.running = False
        self.packet_count = 0
        self.start_time = None
        self.traffic_stats = defaultdict(int)
        self.lock = threading.Lock()
        self._setup_signal_handlers()
        
    def _setup_signal_handlers(self):
        """Setup handlers for graceful shutdown"""
        import signal
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        logger.info("Received shutdown signal, stopping sniffer...")
        self.stop()
        
    def packet_callback(self, packet):
        """Callback function for each captured packet"""
        with self.lock:
            try:
                self.packet_count += 1
                
                if packet.haslayer(IP):
                    ip_layer = packet['IP']
                    src_ip = ip_layer.src
                    dst_ip = ip_layer.dst
                    packet_length = len(packet)
                    
                    self.traffic_stats['total_packets'] += 1
                    
                    if packet.haslayer(TCP):
                        self.traffic_stats['tcp_packets'] += 1
                    elif packet.haslayer(UDP):
                        self.traffic_stats['udp_packets'] += 1
                    elif packet.haslayer(ICMP):
                        self.traffic_stats['icmp_packets'] += 1
                        
                    threats = self.detector.analyze_packet(packet, src_ip)
                    
                    rate_threats = self.detector.check_rate_based(src_ip, datetime.utcnow())
                    threats.extend(rate_threats)
                    
                    for threat in threats:
                        self._handle_threat(packet, src_ip, dst_ip, threat)
                        
                        if AUTO_BLOCK_ENABLED and threat['severity'] in ['HIGH', 'CRITICAL']:
                            self.firewall.block_ip(
                                src_ip,
                                reason=f"{threat['type']}: {threat.get('details', '')}"
                            )
                            
                if self.packet_count % 1000 == 0:
                    self._log_traffic_stats()
                    
            except Exception as e:
                logger.error(f"Error in packet callback: {e}")
    
    def _handle_threat(self, packet, src_ip, dst_ip, threat):
        """Handle a detected threat"""
        try:
            sport = 0
            dport = 0
            
            if packet.haslayer(TCP):
                sport = packet['TCP'].sport
                dport = packet['TCP'].dport
            elif packet.haslayer(UDP):
                sport = packet['UDP'].sport
                dport = packet['UDP'].dport
                
            protocol = "TCP"
            if packet.haslayer(UDP):
                protocol = "UDP"
            elif packet.haslayer(ICMP):
                protocol = "ICMP"
                
            is_blocked = src_ip in self.firewall.blocked_ips
            
            event = ThreatEvent(
                timestamp=datetime.utcnow(),
                source_ip=src_ip,
                destination_ip=dst_ip,
                source_port=sport,
                destination_port=dport,
                protocol=protocol,
                attack_type=threat['type'],
                confidence=threat.get('confidence', 0.0),
                severity=threat['severity'],
                raw_packet=str(packet)[:1000],
                action_taken="blocked" if is_blocked else "alerted",
                blocked=is_blocked,
                extra_data=threat
            )
            
            db = db_session()
            db.add(event)
            db.commit()
            db.close()
            
            logger.warning(
                f"THREAT DETECTED: {threat['type']} from {src_ip}:{sport} "
                f"(Confidence: {threat.get('confidence', 0):.2%}, Severity: {threat['severity']})"
            )
            
        except Exception as e:
            logger.error(f"Error handling threat: {e}")
    
    def _log_traffic_stats(self):
        """Log traffic statistics to database"""
        try:
            db = db_session()
            log = TrafficLog(
                timestamp=datetime.utcnow(),
                total_packets=self.traffic_stats['total_packets'],
                tcp_packets=self.traffic_stats['tcp_packets'],
                udp_packets=self.traffic_stats['udp_packets'],
                icmp_packets=self.traffic_stats['icmp_packets'],
                unique_sources=0,
                unique_destinations=0,
                blocked_count=len(self.firewall.blocked_ips),
                threat_count=0
            )
            db.add(log)
            db.commit()
            db.close()
            
        except Exception as e:
            logger.error(f"Error logging traffic stats: {e}")
    
    def start(self):
        """Start packet sniffing"""
        if self.running:
            logger.warning("Sniffer already running")
            return
            
        self.running = True
        self.start_time = datetime.utcnow()
        logger.info(f"Starting packet sniffer on interface: {self.interface}")
        
        self.sniff_thread = threading.Thread(
            target=self._sniff_loop,
            daemon=True
        )
        self.sniff_thread.start()
        
    def _sniff_loop(self):
        """Main sniffing loop"""
        try:
            sniff(
                iface=self.interface,
                filter=SNIFF_FILTER,
                prn=self.packet_callback,
                store=0,
                stop_filter=lambda x: not self.running
            )
        except Exception as e:
            logger.error(f"Sniffing error: {e}")
            self.running = False
    
    def stop(self):
        """Stop packet sniffing"""
        self.running = False
        logger.info(f"Stopped packet sniffer. Total packets: {self.packet_count}")
        
    def get_stats(self):
        """Get current sniffer statistics"""
        elapsed = (datetime.utcnow() - self.start_time).total_seconds() if self.start_time else 0
        pps = self.packet_count / elapsed if elapsed > 0 else 0
        
        return {
            "running": self.running,
            "packet_count": self.packet_count,
            "packets_per_second": round(pps, 2),
            "elapsed_seconds": round(elapsed, 2),
            "traffic_stats": dict(self.traffic_stats),
            "threats_detected": dict(self.detector.threat_counts),
            "blocked_ips": list(self.firewall.blocked_ips)
        }
    
    def get_recent_threats(self, limit=100):
        """Get recent threat events from database"""
        try:
            db = db_session()
            threats = db.query(ThreatEvent).order_by(
                ThreatEvent.timestamp.desc()
            ).limit(limit).all()
            result = [t.to_dict() for t in threats]
            db.close()
            return result
        except Exception as e:
            logger.error(f"Error getting recent threats: {e}")
            return []
