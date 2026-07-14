#!/usr/bin/env python3
"""
Network Packet Analyzer

Usage:
    python analyzer_ctrlc.py --live -c 5000
    python analyzer_ctrlc.py --live --relaxed
    python analyzer_ctrlc.py -r file.pcap
"""

import argparse
import sys
import time
import math
import socket as py_socket
import platform
import threading
from datetime import datetime
from collections import defaultdict, Counter, deque
from typing import Optional, Dict, List, Tuple, Set
from dataclasses import dataclass, field

# Scapy for pcap I/O only
try:
    from scapy.all import wrpcap, rdpcap, Ether, IP, TCP, UDP, ICMP, Raw, DNS, DNSQR
    from scapy.layers.http import HTTPRequest, HTTPResponse
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False

# Colorama
try:
    from colorama import Fore, Back, Style, init
    init(autoreset=True)
except ImportError:
    class DummyColor:
        def __getattr__(self, name): return ''
    Fore = Back = Style = DummyColor()

# Numpy
try:
    import numpy as np
    NUMPY_ENABLED = True
except ImportError:
    NUMPY_ENABLED = False


# =============================================================================
# CONFIGURATION
# =============================================================================

KNOWN_GOOD_IPS: Set[str] = {
    "91.108.56.0/24", "91.108.23.0/24", "149.154.160.0/22", "149.164.0.0/16",
    "142.250.0.0/15", "172.217.0.0/16", "216.58.0.0/16",
    "104.16.0.0/12", "172.64.0.0/13",
    "13.64.0.0/11", "20.184.0.0/16", "52.96.0.0/12",
    "31.13.64.0/18", "157.240.0.0/16",
}

def ip_in_network(ip: str, network: str) -> bool:
    try:
        ip_parts = list(map(int, ip.split('.')))
        net, mask = network.split('/')
        net_parts = list(map(int, net.split('.')))
        mask_bits = int(mask)
        ip_int = (ip_parts[0] << 24) | (ip_parts[1] << 16) | (ip_parts[2] << 8) | ip_parts[3]
        net_int = (net_parts[0] << 24) | (net_parts[1] << 16) | (net_parts[2] << 8) | net_parts[3]
        mask_int = (0xFFFFFFFF << (32 - mask_bits)) & 0xFFFFFFFF
        return (ip_int & mask_int) == (net_int & mask_int)
    except:
        return False

def is_whitelisted(ip: str) -> bool:
    for network in KNOWN_GOOD_IPS:
        if ip_in_network(ip, network):
            return True
    return False


# =============================================================================
# DATA STRUCTURES
# =============================================================================

@dataclass
class PacketFeatures:
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    packet_size: int
    ttl: int
    tcp_flags: str = ""
    payload_size: int = 0
    dns_query: str = ""
    http_method: str = ""


@dataclass 
class AnomalyAlert:
    timestamp: str
    severity: str
    category: str
    description: str
    source: str
    confidence: float
    raw_data: Dict = field(default_factory=dict)


# =============================================================================
# ANOMALY DETECTION ENGINE
# =============================================================================

class AnomalyDetector:
    SEVERITY = {
        'LOW': Fore.GREEN,
        'MEDIUM': Fore.YELLOW,
        'HIGH': Fore.RED,
        'CRITICAL': Fore.RED + Style.BRIGHT + Back.BLACK
    }
    
    def __init__(self, window_size: int = 100, threshold_mode: str = "normal"):
        self.alerts: deque = deque(maxlen=1000)
        self.features_history: deque = deque(maxlen=window_size)
        self.baseline_stats = {
            'packet_sizes': deque(maxlen=window_size),
            'ports': Counter(),
            'protocols': Counter(),
            'ips': Counter()
        }
        self.ip_reputation: Dict[str, Dict] = defaultdict(lambda: {
            'packet_count': 0,
            'ports_scanned': set(),
            'syn_count': 0,
            'failed_logins': 0,
            'dns_queries': Counter(),
            'data_exfil': 0
        })
        
        self.thresholds = self._get_thresholds(threshold_mode)
        self.suspicious_ports = {4444, 5555, 6666, 7777, 8888, 31337, 12345}
        self._last_alert_time: Dict[str, float] = {}
        self._alert_cooldown = 5.0
        
    def _get_thresholds(self, mode: str) -> Dict:
        thresholds = {
            'relaxed': {
                'port_scan': 20, 'syn_flood': 100, 'dns_tunnel': 100,
                'data_exfil': 500000, 'brute_force': 20,
            },
            'normal': {
                'port_scan': 10, 'syn_flood': 50, 'dns_tunnel': 50,
                'data_exfil': 100000, 'brute_force': 10,
            },
            'strict': {
                'port_scan': 5, 'syn_flood': 20, 'dns_tunnel': 30,
                'data_exfil': 50000, 'brute_force': 5,
            }
        }
        return thresholds.get(mode, thresholds['normal'])
    
    def _calculate_zscore(self, value: float, history: deque) -> float:
        if not history or len(history) < 5:
            return 0.0
        if NUMPY_ENABLED:
            arr = np.array(list(history))
            mean, std = np.mean(arr), np.std(arr)
            return abs((value - mean) / std) if std > 0 else 0.0
        else:
            arr = list(history)
            mean = sum(arr) / len(arr)
            variance = sum((x - mean) ** 2 for x in arr) / len(arr)
            std = math.sqrt(variance)
            return abs((value - mean) / std) if std > 0 else 0.0
    
    def _add_alert(self, severity: str, category: str, description: str,
                   source: str, confidence: float, raw_data: Dict = None):
        alert_key = f"{category}:{source}"
        now = time.time()
        if alert_key in self._last_alert_time:
            if now - self._last_alert_time[alert_key] < self._alert_cooldown:
                return None
        self._last_alert_time[alert_key] = now
        
        alert = AnomalyAlert(
            timestamp=datetime.now().strftime("%H:%M:%S"),
            severity=severity, category=category, description=description,
            source=source, confidence=confidence, raw_data=raw_data or {}
        )
        self.alerts.append(alert)
        return alert
    
    def analyze(self, features: PacketFeatures) -> List[AnomalyAlert]:
        new_alerts = []
        ip_rep = self.ip_reputation[features.src_ip]
        ip_rep['packet_count'] += 1
        
        self.baseline_stats['packet_sizes'].append(features.packet_size)
        self.baseline_stats['ports'][features.dst_port] += 1
        self.baseline_stats['protocols'][features.protocol] += 1
        self.baseline_stats['ips'][features.src_ip] += 1
        
        src_whitelisted = is_whitelisted(features.src_ip)
        dst_whitelisted = is_whitelisted(features.dst_ip)
        
        # 1. PORT SCAN
        ip_rep['ports_scanned'].add(features.dst_port)
        if len(ip_rep['ports_scanned']) > self.thresholds['port_scan']:
            alert = self._add_alert(
                'HIGH', 'PORT_SCAN',
                f"Scanning {len(ip_rep['ports_scanned'])} ports",
                features.src_ip, 0.85,
                {'ports': list(ip_rep['ports_scanned'])[:10]}
            )
            if alert:
                new_alerts.append(alert)
        
        # 2. SYN FLOOD
        if 'S' in features.tcp_flags and 'A' not in features.tcp_flags:
            ip_rep['syn_count'] += 1
            if ip_rep['syn_count'] > self.thresholds['syn_flood']:
                alert = self._add_alert(
                    'CRITICAL', 'SYN_FLOOD',
                    f"SYN flood: {ip_rep['syn_count']} packets",
                    features.src_ip, 0.92,
                    {'syn_count': ip_rep['syn_count']}
                )
                if alert:
                    new_alerts.append(alert)
                ip_rep['syn_count'] = 0
        
        # 3. DNS TUNNELING
        if features.dns_query:
            query_len = len(features.dns_query)
            ip_rep['dns_queries'][features.dns_query] += 1
            if query_len > self.thresholds['dns_tunnel']:
                alert = self._add_alert(
                    'MEDIUM', 'DNS_TUNNELING',
                    f"Long DNS query: {query_len} chars",
                    features.src_ip, 0.75,
                    {'query': features.dns_query[:50] + '...'}
                )
                if alert:
                    new_alerts.append(alert)
        
        # 4. DATA EXFILTRATION
        if not dst_whitelisted and features.packet_size > 1000:
            ip_rep['data_exfil'] += features.packet_size
            if ip_rep['data_exfil'] > self.thresholds['data_exfil']:
                alert = self._add_alert(
                    'HIGH', 'DATA_EXFILTRATION',
                    f"Large transfer: {ip_rep['data_exfil']/1024:.0f} KB",
                    features.src_ip, 0.80,
                    {'total_bytes': ip_rep['data_exfil']}
                )
                if alert:
                    new_alerts.append(alert)
                ip_rep['data_exfil'] = 0
        
        # 5. STATISTICAL ANOMALY
        if len(self.baseline_stats['packet_sizes']) > 10:
            zscore = self._calculate_zscore(features.packet_size, self.baseline_stats['packet_sizes'])
            if zscore > 3.0:
                alert = self._add_alert(
                    'LOW', 'STATISTICAL_ANOMALY',
                    f"Unusual size: {features.packet_size}B (z={zscore:.1f})",
                    features.src_ip, min(zscore/5, 0.9),
                    {'zscore': zscore}
                )
                if alert:
                    new_alerts.append(alert)
        
        # 6. SUSPICIOUS PORT
        if features.dst_port in self.suspicious_ports:
            alert = self._add_alert(
                'MEDIUM', 'SUSPICIOUS_PORT',
                f"Suspicious port: {features.dst_port}",
                features.src_ip, 0.78,
                {'port': features.dst_port}
            )
            if alert:
                new_alerts.append(alert)
        
        # 7. BRUTE FORCE
        if features.dst_port in [22, 3389, 21]:
            ip_rep['failed_logins'] += 1
            if ip_rep['failed_logins'] > self.thresholds['brute_force']:
                alert = self._add_alert(
                    'HIGH', 'BRUTE_FORCE',
                    f"Brute force on port {features.dst_port}",
                    features.src_ip, 0.88,
                    {'attempts': ip_rep['failed_logins']}
                )
                if alert:
                    new_alerts.append(alert)
                ip_rep['failed_logins'] = 0
        
        self.features_history.append(features)
        return new_alerts
    
    def get_threat_score(self, ip: str) -> float:
        rep = self.ip_reputation[ip]
        score = min(len(rep['ports_scanned']) * 5, 30)
        score += min(rep['syn_count'] * 2, 25)
        score += min(sum(rep['dns_queries'].values()) * 0.5, 20)
        score += min(rep['data_exfil'] / 10000, 25)
        return min(score, 100)
    
    def get_top_threats(self, n: int = 5) -> List[Tuple[str, float]]:
        threats = [(ip, self.get_threat_score(ip)) for ip in self.ip_reputation.keys()]
        return sorted(threats, key=lambda x: x[1], reverse=True)[:n]


# =============================================================================
# PACKET PROCESSOR
# =============================================================================

class PacketProcessor:
    def __init__(self, detector: AnomalyDetector):
        self.detector = detector
        self.last_packet_time = time.time()
        self.packet_count = 0
        
    def extract_features_raw(self, raw_data: bytes) -> Optional[PacketFeatures]:
        if len(raw_data) < 20:
            return None
            
        timestamp = time.time()
        version_ihl = raw_data[0]
        ihl = (version_ihl & 0x0F) * 4
        
        if len(raw_data) < ihl:
            return None
            
        protocol_num = raw_data[9]
        protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
        
        features = PacketFeatures(
            timestamp=timestamp,
            src_ip=".".join(str(b) for b in raw_data[12:16]),
            dst_ip=".".join(str(b) for b in raw_data[16:20]),
            src_port=0, dst_port=0,
            protocol=protocol_map.get(protocol_num, f"PROTO_{protocol_num}"),
            packet_size=len(raw_data),
            ttl=raw_data[8]
        )
        
        if protocol_num in [6, 17] and len(raw_data) >= ihl + 4:
            features.src_port = (raw_data[ihl] << 8) | raw_data[ihl + 1]
            features.dst_port = (raw_data[ihl + 2] << 8) | raw_data[ihl + 3]
            
            if protocol_num == 6 and len(raw_data) >= ihl + 14:
                flags_byte = raw_data[ihl + 13]
                flags = []
                if flags_byte & 0x02: flags.append('S')
                if flags_byte & 0x10: flags.append('A')
                if flags_byte & 0x01: flags.append('F')
                if flags_byte & 0x04: flags.append('R')
                if flags_byte & 0x08: flags.append('P')
                features.tcp_flags = ''.join(flags)
                data_offset = ((raw_data[ihl + 12] >> 4) & 0x0F) * 4
                features.payload_size = max(0, len(raw_data) - ihl - data_offset)
            elif protocol_num == 17:
                features.payload_size = max(0, len(raw_data) - ihl - 8)
        
        return features
    
    def extract_features_scapy(self, packet) -> Optional[PacketFeatures]:
        if packet is None:
            return None
            
        timestamp = time.time()
        features = PacketFeatures(
            timestamp=timestamp, src_ip="", dst_ip="", src_port=0, dst_port=0,
            protocol="UNKNOWN", packet_size=len(packet) if packet else 0, ttl=64
        )
        
        if packet.haslayer(IP):
            ip = packet[IP]
            features.src_ip = ip.src
            features.dst_ip = ip.dst
            features.ttl = ip.ttl
            
            if packet.haslayer(TCP):
                tcp = packet[TCP]
                features.protocol = "TCP"
                features.src_port = tcp.sport
                features.dst_port = tcp.dport
                flags = []
                if tcp.flags.S: flags.append('S')
                if tcp.flags.A: flags.append('A')
                if tcp.flags.F: flags.append('F')
                if tcp.flags.R: flags.append('R')
                if tcp.flags.P: flags.append('P')
                features.tcp_flags = ''.join(flags)
            elif packet.haslayer(UDP):
                udp = packet[UDP]
                features.protocol = "UDP"
                features.src_port = udp.sport
                features.dst_port = udp.dport
            elif packet.haslayer(ICMP):
                features.protocol = "ICMP"
        else:
            features.src_ip = "N/A"
            features.dst_ip = "N/A"
        
        if packet.haslayer(DNS):
            dns = packet[DNS]
            if dns.haslayer(DNSQR):
                features.dns_query = str(dns[DNSQR].qname)
        
        if packet.haslayer(HTTPRequest):
            http = packet[HTTPRequest]
            features.http_method = (http.Method.decode() if hasattr(http.Method, 'decode') else str(http.Method))
        
        if packet.haslayer(Raw):
            features.payload_size = len(bytes(packet[Raw].load))
        
        return features
    
    def process(self, packet) -> Tuple[Optional[PacketFeatures], List[AnomalyAlert]]:
        self.packet_count += 1
        if isinstance(packet, bytes):
            features = self.extract_features_raw(packet)
        else:
            features = self.extract_features_scapy(packet)
        if features is None:
            return None, []
        alerts = self.detector.analyze(features)
        return features, alerts


# =============================================================================
# LIVE STATUS DISPLAY
# =============================================================================

class LiveStatus:
    def __init__(self, packet_count_ref, detector: AnomalyDetector):
        self.packet_count_ref = packet_count_ref
        self.detector = detector
        self._last_count = 0
        self._last_time = time.time()
        self._last_line_len = 0
        
    def update(self, force=False):
        now = time.time()
        elapsed = now - self._last_time
        
        if elapsed >= 1.0 or force:
            current_count = self.packet_count_ref()
            pps = (current_count - self._last_count) / elapsed if elapsed > 0 else 0
            self._last_count = current_count
            self._last_time = now
            
            status = (f"\r{Fore.CYAN}[{datetime.now().strftime('%H:%M:%S')}] "
                      f"Pkts: {current_count:,} | "
                      f"Rate: {pps:6.1f}/s | "
                      f"Alerts: {len(self.detector.alerts):3} | "
                      f"TopThreat: {self._get_top_threat()}{Style.RESET_ALL}")
            
            padding = max(0, self._last_line_len - len(status))
            print(f"{status}{' ' * padding}", end='', flush=True)
            self._last_line_len = len(status)
    
    def _get_top_threat(self) -> str:
        threats = self.detector.get_top_threats(1)
        if threats:
            ip, score = threats[0]
            color = Fore.RED if score > 50 else Fore.YELLOW if score > 20 else Fore.GREEN
            return f"{color}{ip[:15]}({score:.0f}){Style.RESET_ALL}"
        return "None"


# =============================================================================
# WINDOWS RAW SOCKET CAPTURE - FIXED CTRL+C
# =============================================================================

class WindowsRawCapture:
    def __init__(self, detector: AnomalyDetector):
        self.detector = detector
        self.running = True
        self.packet_count = 0
        self.captured_packets = []
        self.processor = PacketProcessor(detector)
        
    def _print_alert(self, alert: AnomalyAlert):
        color = self.detector.SEVERITY[alert.severity]
        print(f"\n{'┌' + '─'*78 + '┐'}")
        print(f"│ {color}[{alert.severity:8}]{Style.RESET_ALL} {alert.category:20} {alert.timestamp:8} {' '*32}│")
        print(f"│ Source: {alert.source:20} Confidence: {alert.confidence:.0%} {' '*38}│")
        print(f"│ {alert.description[:76]:76} │")
        print(f"{'└' + '─'*78 + '┘'}")
    
    def get_local_ip(self) -> str:
        try:
            s = py_socket.socket(py_socket.AF_INET, py_socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except:
            return "127.0.0.1"
    
    def capture(self, interface_ip=None, count=0, timeout=None):
        print(f"\n{Fore.CYAN}Setting up Windows raw socket...{Style.RESET_ALL}")
        
        if not interface_ip or interface_ip == "0.0.0.0":
            bind_ip = self.get_local_ip()
        else:
            bind_ip = interface_ip
            
        print(f"{Fore.CYAN}Binding to: {bind_ip}{Style.RESET_ALL}")
        
        sock = None
        try:
            sock = py_socket.socket(py_socket.AF_INET, py_socket.SOCK_RAW, 
                                   py_socket.IPPROTO_IP)
            sock.bind((bind_ip, 0))
            
            try:
                RCVALL_ON = 1
                sock.ioctl(py_socket.SIO_RCVALL, RCVALL_ON)
                print(f"{Fore.GREEN}✓ Promiscuous mode enabled{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.YELLOW}⚠️  Promiscuous mode: {e}{Style.RESET_ALL}")
            
            print(f"{Fore.GREEN}✓ Raw socket ready{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Capturing... Press Ctrl+C to stop{Style.RESET_ALL}\n")
            
            status = LiveStatus(lambda: self.packet_count, self.detector)
            
            packets_received = 0
            start_time = time.time()
            
            # CRITICAL FIX: Use short timeout in loop so Ctrl+C works
            while self.running and (count == 0 or packets_received < count):
                if timeout and (time.time() - start_time) > timeout:
                    break
                
                # Short timeout allows checking self.running frequently
                sock.settimeout(0.5)  # 500ms timeout
                
                try:
                    raw_data, addr = sock.recvfrom(65535)
                    
                    if raw_data:
                        packets_received += 1
                        self.packet_count += 1
                        
                        features, alerts = self.processor.process(raw_data)
                        
                        if features:
                            self.captured_packets.append(raw_data)
                            if alerts:
                                for alert in alerts:
                                    self._print_alert(alert)
                        
                        if packets_received % 10 == 0:
                            status.update()
                            
                except py_socket.timeout:
                    # Normal - just check if we should continue
                    continue
                except KeyboardInterrupt:
                    # Ctrl+C pressed!
                    print(f"\n{Fore.YELLOW}⚠️  Ctrl+C detected, stopping...{Style.RESET_ALL}")
                    self.running = False
                    break
                except OSError as e:
                    if e.winerror == 10004:  # Interrupted
                        break
                    print(f"\n{Fore.RED}Socket error: {e}{Style.RESET_ALL}")
                    break
                except Exception:
                    continue
            
            status.update(force=True)
            print(f"\n\n{Fore.GREEN}✓ Captured {packets_received} packets{Style.RESET_ALL}")
            return True
            
        except PermissionError:
            print(f"\n{Fore.RED}❌ Administrator privileges required!{Style.RESET_ALL}")
            return False
        except Exception as e:
            print(f"\n{Fore.RED}❌ Error: {e}{Style.RESET_ALL}")
            return False
        finally:
            # ALWAYS cleanup
            if sock:
                try:
                    sock.ioctl(py_socket.SIO_RCVALL, 0)
                except:
                    pass
                try:
                    sock.close()
                except:
                    pass


# =============================================================================
# PCAP ANALYZER
# =============================================================================

class PcapAnalyzer:
    def __init__(self, detector: AnomalyDetector):
        self.detector = detector
        self.processor = PacketProcessor(detector)
        self.packet_count = 0
        
    def analyze(self, filename: str):
        if not SCAPY_OK:
            print(f"{Fore.RED}❌ Scapy required{Style.RESET_ALL}")
            return False
            
        print(f"\n{Fore.CYAN}📂 Loading: {filename}{Style.RESET_ALL}")
        try:
            packets = rdpcap(filename)
            print(f"{Fore.GREEN}✓ Loaded {len(packets)} packets{Style.RESET_ALL}\n")
            
            for i, packet in enumerate(packets):
                if not self._check_interrupt():
                    break
                    
                self.packet_count += 1
                features, alerts = self.processor.process(packet)
                if alerts:
                    for alert in alerts:
                        self._print_alert(alert)
                
                if (i + 1) % 50 == 0 or i == len(packets) - 1:
                    pct = (i + 1) / len(packets) * 100
                    bar = '█' * int(pct // 5) + '░' * (20 - int(pct // 5))
                    print(f"\r{Fore.CYAN}Progress: [{bar}] {pct:.1f}%{Style.RESET_ALL}", end='')
                    
            print(f"\n{Fore.GREEN}✓ Analysis complete{Style.RESET_ALL}")
            return True
            
        except FileNotFoundError:
            print(f"{Fore.RED}❌ File not found: {filename}{Style.RESET_ALL}")
            return False
        except Exception as e:
            print(f"{Fore.RED}❌ Error: {e}{Style.RESET_ALL}")
            return False
    
    def _check_interrupt(self):
        """Check for Ctrl+C during file processing."""
        try:
            return True
        except KeyboardInterrupt:
            return False
    
    def _print_alert(self, alert: AnomalyAlert):
        color = self.detector.SEVERITY[alert.severity]
        print(f"\n{'┌' + '─'*78 + '┐'}")
        print(f"│ {color}[{alert.severity:8}]{Style.RESET_ALL} {alert.category:20} {alert.timestamp:8} {' '*32}│")
        print(f"│ Source: {alert.source:20} Confidence: {alert.confidence:.0%} {' '*38}│")
        print(f"│ {alert.description[:76]:76} │")
        print(f"{'└' + '─'*78 + '┘'}")


# =============================================================================
# MAIN APPLICATION
# =============================================================================

class NetworkAnalyzer:
    def __init__(self, interface=None, packet_count=0, 
                 save_file=None, read_file=None, threshold_mode="normal"):
        self.interface = interface
        self.packet_count = packet_count
        self.save_file = save_file
        self.read_file = read_file
        self.threshold_mode = threshold_mode
        
        self.detector = AnomalyDetector(threshold_mode=threshold_mode)
        self.running = True
        
    def _print_final_report(self, total_packets: int):
        print(f"\n{'='*80}")
        print(f"{Fore.CYAN + Style.BRIGHT}{'FINAL SECURITY REPORT':^80}{Style.RESET_ALL}")
        print(f"{'='*80}")
        print(f"Mode:     {self.threshold_mode.upper()}")
        print(f"Packets:  {total_packets:,}")
        print(f"Anomalies: {len(self.detector.alerts)}")
        
        if self.detector.alerts:
            print(f"\n{Fore.RED}🚨 ALERT SUMMARY:{Style.RESET_ALL}")
            severity_counts = Counter(a.severity for a in self.detector.alerts)
            for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                count = severity_counts.get(sev, 0)
                color = self.detector.SEVERITY[sev]
                print(f"  {color}{sev:10}{Style.RESET_ALL}: {count}")
            
            print(f"\n{Fore.YELLOW}📋 DETAILED ALERTS:{Style.RESET_ALL}")
            for alert in list(self.detector.alerts)[-15:]:
                color = self.detector.SEVERITY[alert.severity]
                print(f"  [{color}{alert.severity}{Style.RESET_ALL}] "
                      f"{alert.timestamp} | {alert.category:20} | "
                      f"{alert.source:15} | {alert.description[:40]}")
        
        print(f"\n{Fore.CYAN}🎯 TOP THREATS:{Style.RESET_ALL}")
        for ip, score in self.detector.get_top_threats(5):
            color = Fore.RED if score > 50 else Fore.YELLOW if score > 20 else Fore.GREEN
            print(f"  {color}{ip:20}{Style.RESET_ALL} Score: {score:.1f}/100")
        
        print(f"\n{Fore.CYAN}📈 PROTOCOLS:{Style.RESET_ALL}")
        for proto, count in self.detector.baseline_stats['protocols'].most_common():
            print(f"  {proto:10}: {count}")
        
        print(f"{'='*80}\n")
    
    def start(self):
        print(f"\n{'='*80}")
        print(f"{Fore.CYAN + Style.BRIGHT}{'🔒 NETWORK SECURITY ANALYZER':^80}{Style.RESET_ALL}")
        print(f"{'='*80}")
        
        if self.read_file:
            print(f"Mode:     OFFLINE PCAP")
            print(f"File:     {self.read_file}")
            print(f"Sensitivity: {self.threshold_mode}")
            print(f"{'='*80}")
            
            analyzer = PcapAnalyzer(self.detector)
            try:
                success = analyzer.analyze(self.read_file)
                if success:
                    self._print_final_report(analyzer.packet_count)
            except KeyboardInterrupt:
                print(f"\n{Fore.YELLOW}⚠️  Interrupted by user{Style.RESET_ALL}")
                self._print_final_report(analyzer.packet_count)
            return
        
        print(f"Mode:     LIVE CAPTURE")
        print(f"Platform: {platform.system()} {platform.release()}")
        print(f"Interface:{self.interface or 'auto-detect'}")
        print(f"Count:    {'unlimited' if self.packet_count == 0 else self.packet_count}")
        print(f"Sensitivity: {self.threshold_mode}")
        print(f"Save:     {self.save_file or 'none (use -w to save)'}")
        print(f"{'='*80}")
        
        capture = WindowsRawCapture(self.detector)
        capture.running = True
        
        try:
            success = capture.capture(
                interface_ip=self.interface,
                count=self.packet_count,
                timeout=None
            )
            
            if success:
                self._print_final_report(capture.packet_count)
                
                # ONLY save if explicitly requested with -w
                if self.save_file and capture.captured_packets and SCAPY_OK:
                    try:
                        scapy_packets = []
                        for raw_data in capture.captured_packets:
                            if len(raw_data) >= 20:
                                scapy_packets.append(IP(raw_data))
                        if scapy_packets:
                            wrpcap(self.save_file, scapy_packets)
                            print(f"{Fore.GREEN}💾 Saved {len(scapy_packets)} packets to {self.save_file}{Style.RESET_ALL}")
                    except Exception as e:
                        print(f"{Fore.RED}❌ Save error: {e}{Style.RESET_ALL}")
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}⚠️  Interrupted by user{Style.RESET_ALL}")
            capture.running = False
            self._print_final_report(capture.packet_count)


def generate_sample_pcap(filename: str = "sample_traffic.pcap"):
    if not SCAPY_OK:
        print(f"{Fore.RED}❌ Scapy required{Style.RESET_ALL}")
        return
        
    print(f"{Fore.CYAN}🎲 Generating: {filename}{Style.RESET_ALL}")
    packets = []
    
    for i in range(20):
        pkt = Ether()/IP(src="192.168.1.100", dst="93.184.216.34")/TCP(sport=12345+i, dport=80, flags="PA")/Raw(load=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        packets.append(pkt)
    
    for port in range(20, 40):
        pkt = Ether()/IP(src="10.0.0.50", dst="192.168.1.1")/TCP(sport=54321, dport=port, flags="S")
        packets.append(pkt)
    
    long_query = "a" * 60 + ".example.com"
    pkt = Ether()/IP(src="192.168.1.105", dst="8.8.8.8")/UDP(sport=12345, dport=53)/DNS(qd=DNSQR(qname=long_query))
    packets.append(pkt)
    
    for i in range(60):
        pkt = Ether()/IP(src="172.16.0.99", dst="192.168.1.10")/TCP(sport=40000+i, dport=80, flags="S")
        packets.append(pkt)
    
    for i in range(10):
        pkt = Ether()/IP(src="192.168.1.200", dst="185.220.101.42")/TCP(sport=4444, dport=54321, flags="PA")/Raw(load=b"X" * 5000)
        packets.append(pkt)
    
    for i in range(15):
        pkt = Ether()/IP(src="10.0.0.77", dst="192.168.1.5")/TCP(sport=55000+i, dport=22, flags="S")
        packets.append(pkt)
    
    wrpcap(filename, packets)
    print(f"{Fore.GREEN}✓ Generated {len(packets)} packets{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}💡 Run: python analyzer_ctrlc.py -r {filename}{Style.RESET_ALL}\n")


def main():
    parser = argparse.ArgumentParser(
        description="Network Security Analyzer - Ctrl+C Fixed",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python analyzer_ctrlc.py --live -c 5000
  python analyzer_ctrlc.py --live --relaxed
  python analyzer_ctrlc.py -r sample.pcap
        """
    )
    
    parser.add_argument('--live', action='store_true', help='Live capture')
    parser.add_argument('-i', '--interface', help='Local IP to bind to')
    parser.add_argument('-c', '--count', type=int, default=0, help='Packet count (0=unlimited)')
    parser.add_argument('-w', '--write', help='Save pcap (ONLY if specified)')
    parser.add_argument('-r', '--read', help='Read pcap file')
    parser.add_argument('--generate', action='store_true', help='Generate sample')
    
    threshold_group = parser.add_mutually_exclusive_group()
    threshold_group.add_argument('--relaxed', action='store_true', help='Fewer alerts')
    threshold_group.add_argument('--strict', action='store_true', help='More alerts')
    
    args = parser.parse_args()
    
    threshold_mode = "normal"
    if args.relaxed:
        threshold_mode = "relaxed"
    elif args.strict:
        threshold_mode = "strict"
    
    if args.generate:
        generate_sample_pcap()
        return
    
    analyzer = NetworkAnalyzer(
        interface=args.interface,
        packet_count=args.count,
        save_file=args.write,
        read_file=args.read,
        threshold_mode=threshold_mode
    )
    
    analyzer.start()


if __name__ == "__main__":
    main()
