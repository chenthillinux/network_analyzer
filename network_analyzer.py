#!/usr/bin/env python3
import pyshark
import argparse
import os
import re
import statistics
import datetime
import sys
from collections import defaultdict, Counter
import matplotlib.pyplot as plt
import numpy as np
from concurrent.futures import ThreadPoolExecutor
import json
import csv
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("network_analyzer")


class NetworkAnalyzer:
    """Comprehensive network analysis tool for identifying root causes of packet loss."""

    def __init__(self, pcap_file, proc_interrupt_file=None, netstat_file=None, output_dir=None):
        """Initialize the analyzer with input files."""
        # Validate input files
        if not os.path.exists(pcap_file):
            logger.error(f"PCAP file not found: {pcap_file}")
            raise FileNotFoundError(f"PCAP file not found: {pcap_file}")
        if proc_interrupt_file and not os.path.exists(proc_interrupt_file):
            logger.warning(f"Interrupt file not found: {proc_interrupt_file}")
            proc_interrupt_file = None
        if netstat_file and not os.path.exists(netstat_file):
            logger.warning(f"Netstat file not found: {netstat_file}")
            netstat_file = None

        self.pcap_file = pcap_file
        self.proc_interrupt_file = proc_interrupt_file
        self.netstat_file = netstat_file
        self.output_dir = output_dir if output_dir else f"network_analysis_{datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}"

        # Ensure output directory exists
        os.makedirs(self.output_dir, exist_ok=True)

        # Analysis results
        self.packet_stats = {
            "total_packets": 0,
            "dropped_packets": 0,
            "retransmissions": 0,
            "out_of_order": 0,
            "duplicates": 0,
            "zero_window": 0,
            "window_full": 0
        }

        self.latency_data = {
            "tcp_handshakes": [],
            "http_responses": [],
            "dns_lookups": {}
        }

        self.packet_timing = []
        self.conversations = defaultdict(list)
        self.dns_issues = []
        self.tcp_issues = []
        self.daemon_issues = []
        self.udp_transactions = defaultdict(dict)  # Added for UDP response tracking

        self.interrupt_data = None
        self.netstat_data = None

        logger.info(f"NetworkAnalyzer initialized with pcap file: {self.pcap_file}")

    def analyze_pcap(self):
        """Main function to analyze the pcap file for network issues."""
        logger.info("Starting pcap analysis...")

        try:
            # Use tshark for quick packet count if available
            import subprocess
            result = subprocess.run(
                ["tshark", "-r", self.pcap_file, "-q", "-z", "io,stat,0"],
                capture_output=True, text=True, check=True
            )
            packet_count_match = re.search(r'Packets:\s*(\d+)', result.stdout)
            estimated_packets = int(packet_count_match.group(1)) if packet_count_match else None
            if estimated_packets:
                logger.info(f"Estimated packet count: {estimated_packets}")
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            logger.info(f"Falling back to pyshark processing: {str(e)}")
            estimated_packets = None

        self._analyze_with_pyshark()

        # Process system files if provided
        if self.proc_interrupt_file:
            self._analyze_proc_interrupts()
        if self.netstat_file:
            self._analyze_netstat()

        # Generate final report
        report_path = self._generate_report()

        logger.info(f"Analysis complete. Report generated at: {report_path}")
        return self.output_dir

    def _analyze_with_pyshark(self):
        """Analyze packet capture using pyshark."""
        logger.info("Processing packets with pyshark...")

        try:
            # Use FileCapture with display filter to reduce memory usage
            cap = pyshark.FileCapture(self.pcap_file, keep_packets=False, display_filter="ip")

            # Track TCP streams, DNS, and HTTP transactions
            tcp_streams = defaultdict(list)
            dns_transactions = {}
            tcp_handshakes = defaultdict(dict)
            http_transactions = defaultdict(dict)
            dup_detection = set()
            batch_size = 10000  # Process packets in batches to manage memory

            for packet_index, packet in enumerate(cap):
                if packet_index % batch_size == 0:
                    logger.info(f"Processed {packet_index} packets...")

                self.packet_stats["total_packets"] += 1

                # Extract timestamp
                timestamp = float(packet.sniff_timestamp)

                # Conversation tracking
                try:
                    if hasattr(packet, 'ip'):
                        conv_key = f"{packet.ip.src}:{packet.transport_layer.src_port if hasattr(packet, 'transport_layer') else '0'}-" \
                                   f"{packet.ip.dst}:{packet.transport_layer.dst_port if hasattr(packet, 'transport_layer') else '0'}"
                        self.conversations[conv_key].append(timestamp)
                except AttributeError:
                    pass

                # Store packet timing for jitter analysis (limit to 100,000 entries)
                if len(self.packet_timing) < 100000:
                    self.packet_timing.append(timestamp)

                # Analyze TCP packets
                if hasattr(packet, 'tcp'):
                    self._analyze_tcp_packet(packet, tcp_streams, tcp_handshakes, dup_detection)
                    if hasattr(packet, 'http'):
                        self._analyze_http_packet(packet, http_transactions)

                # Analyze DNS packets
                if hasattr(packet, 'dns'):
                    self._analyze_dns_packet(packet, dns_transactions)

                # Check for daemon issues
                self._check_for_daemon_issues(packet)

                # Clear memory periodically
                if packet_index % batch_size == 0:
                    import gc
                    gc.collect()

            # Calculate latency statistics and conversation metrics
            self._calculate_latency_stats(tcp_handshakes, http_transactions, dns_transactions)
            self._analyze_conversations()
            self._finalize_udp_transactions()  # Check for missing UDP responses

            logger.info(f"Finished processing {self.packet_stats['total_packets']} packets")

        except Exception as e:
            logger.error(f"Error during pyshark processing: {str(e)}")
            raise
        finally:
            cap.close()

    def _analyze_tcp_packet(self, packet, tcp_streams, tcp_handshakes, dup_detection):
        """Analyze TCP packet for issues."""
        try:
            stream_id = packet.tcp.stream if hasattr(packet.tcp,
                                                     'stream') else f"{packet.ip.src}:{packet.tcp.srcport}-{packet.ip.dst}:{packet.tcp.dstport}"
            timestamp = float(packet.sniff_timestamp)

            # Duplicate detection
            packet_sig = f"{stream_id}:{packet.tcp.seq}:{packet.tcp.ack}"
            if packet_sig in dup_detection:
                self.packet_stats["duplicates"] += 1
            else:
                dup_detection.add(packet_sig)

            # Track TCP stream
            tcp_streams[stream_id].append({
                'timestamp': timestamp,
                'seq': int(packet.tcp.seq),
                'ack': int(packet.tcp.ack),
                'flags': packet.tcp.flags,
                'len': int(packet.tcp.len) if hasattr(packet.tcp, 'len') else 0
            })

            # TCP handshake analysis
            if hasattr(packet.tcp, 'flags'):
                flags = packet.tcp.flags
                if flags == '0x00000002':  # SYN
                    tcp_handshakes[stream_id]['syn'] = timestamp
                elif flags == '0x00000012':  # SYN-ACK
                    tcp_handshakes[stream_id]['synack'] = timestamp
                elif flags == '0x00000010' and 'synack' in tcp_handshakes[stream_id]:
                    tcp_handshakes[stream_id]['final_ack'] = timestamp

            # Detect TCP issues
            if hasattr(packet.tcp, 'analysis_retransmission'):
                self.packet_stats["retransmissions"] += 1
                self.tcp_issues.append({
                    'type': 'retransmission',
                    'timestamp': timestamp,
                    'stream_id': stream_id,
                    'src': packet.ip.src,
                    'dst': packet.ip.dst,
                    'seq': packet.tcp.seq
                })

            if hasattr(packet.tcp, 'analysis_out_of_order'):
                self.packet_stats["out_of_order"] += 1
                self.tcp_issues.append({
                    'type': 'out_of_order',
                    'timestamp': timestamp,
                    'stream_id': stream_id,
                    'src': packet.ip.src,
                    'dst': packet.ip.dst,
                    'seq': packet.tcp.seq
                })

            if hasattr(packet.tcp, 'window_size') and int(packet.tcp.window_size) == 0:
                self.packet_stats["zero_window"] += 1
                self.tcp_issues.append({
                    'type': 'zero_window',
                    'timestamp': timestamp,
                    'stream_id': stream_id,
                    'src': packet.ip.src,
                    'dst': packet.ip.dst
                })

            if hasattr(packet.tcp, 'analysis_window_full'):
                self.packet_stats["window_full"] += 1
                self.tcp_issues.append({
                    'type': 'window_full',
                    'timestamp': timestamp,
                    'stream_id': stream_id,
                    'src': packet.ip.src,
                    'dst': packet.ip.dst
                })

            if hasattr(packet.tcp, 'flags') and int(packet.tcp.flags, 16) & 0x04:
                self.tcp_issues.append({
                    'type': 'reset',
                    'timestamp': timestamp,
                    'stream_id': stream_id,
                    'src': packet.ip.src,
                    'dst': packet.ip.dst
                })

        except AttributeError as e:
            logger.debug(f"Skipping incomplete TCP packet: {str(e)}")

    def _analyze_http_packet(self, packet, http_transactions):
        """Analyze HTTP packets for latency issues."""
        try:
            timestamp = float(packet.sniff_timestamp)
            stream_id = packet.tcp.stream if hasattr(packet.tcp,
                                                     'stream') else f"{packet.ip.src}:{packet.tcp.srcport}-{packet.ip.dst}:{packet.tcp.dstport}"

            if hasattr(packet.http, 'request'):
                http_transactions[stream_id]['request'] = {
                    'timestamp': timestamp,
                    'method': packet.http.request_method if hasattr(packet.http, 'request_method') else 'UNKNOWN',
                    'uri': packet.http.request_uri if hasattr(packet.http, 'request_uri') else 'UNKNOWN'
                }

            if hasattr(packet.http, 'response') and 'request' in http_transactions[stream_id]:
                request_time = http_transactions[stream_id]['request']['timestamp']
                response_time = timestamp - request_time

                self.latency_data["http_responses"].append({
                    'stream_id': stream_id,
                    'latency': response_time,
                    'status_code': packet.http.response_code if hasattr(packet.http, 'response_code') else 'UNKNOWN',
                    'uri': http_transactions[stream_id]['request']['uri']
                })

        except AttributeError as e:
            logger.debug(f"Skipping incomplete HTTP packet: {str(e)}")

    def _analyze_dns_packet(self, packet, dns_transactions):
        """Analyze DNS packets for latency and issues."""
        try:
            timestamp = float(packet.sniff_timestamp)
            query_id = packet.dns.id

            if not packet.dns.flags_response == '1':  # Query
                dns_transactions[query_id] = {
                    'query': packet.dns.qry_name,
                    'timestamp': timestamp,
                    'type': packet.dns.qry_type if hasattr(packet.dns, 'qry_type') else 'UNKNOWN'
                }
            else:  # Response
                if query_id in dns_transactions:
                    query_time = dns_transactions[query_id]['timestamp']
                    response_time = timestamp - query_time

                    has_error = hasattr(packet.dns, 'flags_rcode') and packet.dns.flags_rcode != '0'
                    error_type = None
                    if has_error:
                        error_map = {
                            '1': 'FORMAT_ERROR',
                            '2': 'SERVER_FAILURE',
                            '3': 'NAME_ERROR',
                            '4': 'NOT_IMPLEMENTED',
                            '5': 'REFUSED'
                        }
                        error_type = error_map.get(packet.dns.flags_rcode, f"UNKNOWN_ERROR({packet.dns.flags_rcode})")

                    query_name = dns_transactions[query_id]['query']
                    self.latency_data["dns_lookups"].setdefault(query_name, []).append(response_time)

                    if has_error or response_time > 0.5:
                        self.dns_issues.append({
                            'query': query_name,
                            'latency': response_time,
                            'timestamp': timestamp,
                            'has_error': has_error,
                            'error_type': error_type,
                            'slow': response_time > 0.5
                        })

                    del dns_transactions[query_id]  # Clean up to save memory

        except AttributeError as e:
            logger.debug(f"Skipping incomplete DNS packet: {str(e)}")

    def _check_for_daemon_issues(self, packet):
        """Check for indications of daemon-related issues (TCP and UDP)."""
        try:
            if not (hasattr(packet, 'tcp') or hasattr(packet, 'udp')):
                return

            transport_layer = 'tcp' if hasattr(packet, 'tcp') else 'udp'
            src_port = int(getattr(packet, transport_layer).srcport)
            dst_port = int(getattr(packet, transport_layer).dstport)

            daemon_ports = [22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 5432, 6379, 27017]
            if src_port not in daemon_ports and dst_port not in daemon_ports:
                return

            daemon_port = src_port if src_port in daemon_ports else dst_port
            timestamp = float(packet.sniff_timestamp)
            conv_key = f"{packet.ip.src}:{packet[transport_layer].srcport}-{packet.ip.dst}:{packet[transport_layer].dstport}"

            if transport_layer == 'tcp' and hasattr(packet.tcp, 'flags'):
                flags = int(packet.tcp.flags, 16)
                if flags & 0x04 and not (flags & 0x01):  # RST without FIN
                    self.daemon_issues.append({
                        'timestamp': timestamp,
                        'port': daemon_port,
                        'type': 'unexpected_reset',
                        'src': packet.ip.src,
                        'dst': packet.ip.dst
                    })

            elif transport_layer == 'udp':
                # Track UDP requests and responses
                if dst_port in daemon_ports:
                    self.udp_transactions[conv_key]['request'] = {'timestamp': timestamp, 'port': dst_port}
                elif src_port in daemon_ports and conv_key in self.udp_transactions:
                    self.udp_transactions[conv_key]['response'] = {'timestamp': timestamp}

        except AttributeError as e:
            logger.debug(f"Skipping packet for daemon analysis: {str(e)}")

    def _finalize_udp_transactions(self):
        """Check for missing UDP responses to detect daemon issues."""
        timeout_threshold = 5.0  # 5 seconds
        current_time = max(self.packet_timing, default=0)

        for conv_key, transaction in list(self.udp_transactions.items()):
            if 'request' in transaction and 'response' not in transaction:
                request_time = transaction['request']['timestamp']
                if current_time - request_time > timeout_threshold:
                    self.daemon_issues.append({
                        'timestamp': request_time,
                        'port': transaction['request']['port'],
                        'type': 'no_response',
                        'src': conv_key.split('-')[0].split(':')[0],
                        'dst': conv_key.split('-')[1].split(':')[0]
                    })
            del self.udp_transactions[conv_key]  # Clean up

    def _calculate_latency_stats(self, tcp_handshakes, http_transactions, dns_transactions):
        """Calculate various latency statistics."""
        for stream_id, handshake in tcp_handshakes.items():
            if all(k in handshake for k in ['syn', 'synack', 'final_ack']):
                handshake_time = handshake['final_ack'] - handshake['syn']
                server_time = handshake['synack'] - handshake['syn']

                self.latency_data["tcp_handshakes"].append({
                    'stream_id': stream_id,
                    'total_time': handshake_time,
                    'server_time': server_time,
                    'client_time': handshake['final_ack'] - handshake['synack']
                })

    def _analyze_conversations(self):
        """Analyze conversation patterns for insights."""
        for conv_key, timestamps in self.conversations.items():
            if len(timestamps) < 2:
                continue
            gaps = [timestamps[i] - timestamps[i - 1] for i in range(1, len(timestamps))]
            if gaps:
                avg_gap = sum(gaps) / len(gaps)
                max_gap = max(gaps)
                if max_gap > avg_gap * 5 and max_gap > 1.0:
                    self.tcp_issues.append({
                        'type': 'suspicious_gap',
                        'conversation': conv_key,
                        'max_gap': max_gap,
                        'avg_gap': avg_gap,
                        'timestamp': timestamps[gaps.index(max_gap) + 1]
                    })

    def _analyze_proc_interrupts(self):
        """Analyze /proc/interrupts for NIC interrupt issues."""
        logger.info("Analyzing /proc/interrupts file...")

        try:
            with open(self.proc_interrupt_file, 'r') as f:
                lines = f.readlines()

            if not lines:
                logger.warning("Interrupt file is empty")
                return

            cpu_count = len(lines[0].split()) - 1
            network_interrupts = []

            for line in lines[1:]:
                parts = line.strip().split()
                if len(parts) < cpu_count + 2:
                    continue
                irq = parts[0].strip(':')
                description = ' '.join(parts[cpu_count + 1:])
                if any(net_pattern in description.lower() for net_pattern in
                       ['eth', 'enp', 'wlan', 'ixgbe', 'e1000', 'virtio-net', 'mlx', 'bnx', 'em', 'igb']):
                    cpu_counts = [int(parts[i + 1]) for i in range(cpu_count)]
                    network_interrupts.append({
                        'irq': irq,
                        'description': description,
                        'cpu_counts': cpu_counts,
                        'total': sum(cpu_counts)
                    })

            if network_interrupts:
                cpu_totals = [0] * cpu_count
                for intr in network_interrupts:
                    for i, count in enumerate(intr['cpu_counts']):
                        cpu_totals[i] += count

                if sum(cpu_totals) > 0:
                    avg_interrupts = sum(cpu_totals) / len(cpu_totals)
                    max_imbalance = max(abs(count - avg_interrupts) / avg_interrupts if avg_interrupts > 0 else 0
                                        for count in cpu_totals)
                    self.interrupt_data = {
                        'network_interrupts': network_interrupts,
                        'cpu_totals': cpu_totals,
                        'imbalance_detected': max_imbalance > 0.7,
                        'imbalance_factor': max_imbalance,
                        'max_cpu': cpu_totals.index(max(cpu_totals)) if cpu_totals else None,
                        'min_cpu': cpu_totals.index(min(cpu_totals)) if cpu_totals else None
                    }

            logger.info(f"Found {len(network_interrupts)} network-related interrupts")

        except Exception as e:
            logger.error(f"Error analyzing interrupts: {str(e)}")
            self.interrupt_data = None

    def _analyze_netstat(self):
        """Analyze netstat -s output for TCP/IP stack issues."""
        logger.info("Analyzing netstat statistics...")

        try:
            with open(self.netstat_file, 'r') as f:
                netstat_data = f.read()

            stats = {'tcp': {}, 'udp': {}, 'ip': {}, 'icmp': {}}

            # Parse TCP statistics
            tcp_section = re.search(r'Tcp:(.+?)(?:Udp:|$)', netstat_data, re.DOTALL)
            if tcp_section:
                stats['tcp'] = {
                    'segments_retransmitted': self._extract_metric(tcp_section.group(1),
                                                                   r'(\d+)\s+segments retransmitted'),
                    'bad_segments': self._extract_metric(tcp_section.group(1), r'(\d+)\s+bad segments received'),
                    'resets_sent': self._extract_metric(tcp_section.group(1), r'(\d+)\s+resets sent'),
                    'connections_reset': self._extract_metric(tcp_section.group(1), r'(\d+)\s+connections reset'),
                    'timeouts': self._extract_metric(tcp_section.group(1), r'(\d+)\s+timeouts'),
                    'sack_retransmits': self._extract_metric(tcp_section.group(1), r'(\d+)\s+SACK retransmits'),
                    'fast_retransmits': self._extract_metric(tcp_section.group(1), r'(\d+)\s+fast retransmits'),
                    'retransmit_timeouts': self._extract_metric(tcp_section.group(1), r'(\d+)\s+retransmit timeouts'),
                    'listen_overflows': self._extract_metric(tcp_section.group(1),
                                                             r'(\d+)\s+times the listen queue of a socket overflowed'),
                    'syn_cookies_sent': self._extract_metric(tcp_section.group(1), r'(\d+)\s+SYN cookies sent'),
                    'pruned_sockets': self._extract_metric(tcp_section.group(1),
                                                           r'(\d+)\s+sockets pruned from hashbuckets'),
                    'out_of_memory': self._extract_metric(tcp_section.group(1),
                                                          r'(\d+)\s+times could not allocate \w+ memory'),
                    'receive_buffer_errors': self._extract_metric(tcp_section.group(1),
                                                                  r'(\d+)\s+receive buffer errors'),
                    'send_buffer_errors': self._extract_metric(tcp_section.group(1), r'(\d+)\s+send buffer errors')
                }

            # Parse UDP, IP, ICMP statistics similarly (abridged for brevity)
            udp_section = re.search(r'Udp:(.+?)(?:Ip:|$)', netstat_data, re.DOTALL)
            if udp_section:
                stats['udp'] = {
                    'packets_received': self._extract_metric(udp_section.group(1), r'(\d+)\s+packets received'),
                    'packet_errors': self._extract_metric(udp_section.group(1), r'(\d+)\s+packet receive errors'),
                    'no_port': self._extract_metric(udp_section.group(1), r'(\d+)\s+packets to unknown port received'),
                    'receive_buffer_errors': self._extract_metric(udp_section.group(1),
                                                                  r'(\d+)\s+receive buffer errors'),
                    'send_buffer_errors': self._extract_metric(udp_section.group(1), r'(\d+)\s+send buffer errors')
                }

            self.netstat_data = stats
            self.netstat_data['issues'] = self._identify_netstat_issues(stats)

            logger.info(f"Found {len(self.netstat_data['issues'])} potential issues in netstat statistics")

        except Exception as e:
            logger.error(f"Error analyzing netstat: {str(e)}")
            self.netstat_data = None

    def _identify_netstat_issues(self, stats):
        """Identify issues from netstat statistics."""
        issues = []
        tcp = stats.get('tcp', {})
        if tcp.get('segments_retransmitted', 0) > 1000:
            issues.append({'type': 'high_tcp_retransmits', 'value': tcp['segments_retransmitted'],
                           'severity': 'high' if tcp['segments_retransmitted'] > 10000 else 'medium'})
        if tcp.get('connections_reset', 0) > 100:
            issues.append({'type': 'high_connection_resets', 'value': tcp['connections_reset'],
                           'severity': 'high' if tcp['connections_reset'] > 1000 else 'medium'})
        if tcp.get('listen_overflows', 0) > 0:
            issues.append({'type': 'listen_queue_overflows', 'value': tcp['listen_overflows'], 'severity': 'high'})
        if tcp.get('out_of_memory', 0) > 0:
            issues.append(
                {'type': 'tcp_memory_allocation_failures', 'value': tcp['out_of_memory'], 'severity': 'critical'})
        return issues

    def _extract_metric(self, text, pattern):
        """Extract metrics from netstat output."""
        try:
            match = re.search(pattern, text)
            return int(match.group(1)) if match else 0
        except Exception as e:
            logger.debug(f"Error extracting metric with pattern {pattern}: {str(e)}")
            return 0

    def _generate_report(self):
        """Generate a comprehensive analysis report."""
        logger.info("Generating analysis report...")

        report_file = os.path.join(self.output_dir, "packet_loss_analysis_report.md")
        try:
            with open(report_file, 'w') as f:
                f.write("# Network Packet Loss Analysis Report\n\n")
                f.write(f"Generated on: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"PCAP File: {os.path.basename(self.pcap_file)}\n\n")

                f.write("## Root Cause Analysis Summary\n\n")
                root_causes = self._determine_root_causes()
                if root_causes:
                    f.write("### Identified Issues\n\n")
                    for i, cause in enumerate(root_causes, 1):
                        f.write(f"{i}. **{cause['cause']}**: {cause['description']}\n")
                        f.write(f"   - Severity: {cause['severity']}\n")
                        f.write(f"   - Evidence: {cause['evidence']}\n\n")
                else:
                    f.write("No significant network issues were identified.\n\n")

                f.write("## Packet Statistics\n\n")
                for key, value in self.packet_stats.items():
                    f.write(f"- **{key.replace('_', ' ').title()}**: {value}\n")

                f.write("\n## TCP Performance Analysis\n\n")
                if self.tcp_issues:
                    issue_counts = Counter([issue['type'] for issue in self.tcp_issues])
                    f.write("| Type | Count | Details |\n|------|-------|--------|\n")
                    for issue_type, count in issue_counts.items():
                        f.write(f"| {issue_type} | {count} | {self._get_issue_details(issue_type)} |\n")
                else:
                    f.write("No significant TCP issues detected.\n")

                f.write("\n## DNS Performance Analysis\n\n")
                if self.dns_issues:
                    f.write("| Query | Latency (s) | Issue Type |\n|-------|-------------|------------|\n")
                    for issue in self.dns_issues[:10]:
                        issue_type = f"Error: {issue['error_type']}" if issue['has_error'] else "Slow Response"
                        f.write(f"| {issue['query']} | {issue['latency']:.4f} | {issue_type} |\n")
                    if len(self.dns_issues) > 10:
                        f.write(f"\n*...and {len(self.dns_issues) - 10} more DNS issues*\n")
                else:
                    f.write("No significant DNS issues detected.\n")

                # Additional sections for latency, daemon issues, interrupts, and netstat (abridged for brevity)
                if self.latency_data["tcp_handshakes"]:
                    handshake_times = [h['total_time'] for h in self.latency_data["tcp_handshakes"]]
                    f.write("\n## TCP Handshake Latency\n\n")
                    f.write(f"- **Average**: {sum(handshake_times) / len(handshake_times):.4f} seconds\n")
                    f.write(f"- **Maximum**: {max(handshake_times):.4f} seconds\n")

                if self.daemon_issues:
                    f.write("\n## Daemon-Related Issues\n\n")
                    daemon_issue_counts = Counter([(issue['type'], issue['port']) for issue in self.daemon_issues])
                    f.write("| Type | Port | Count | Details |\n|------|------|-------|--------|\n")
                    for (issue_type, port), count in daemon_issue_counts.items():
                        f.write(
                            f"| {issue_type} | {port} | {count} | {self._get_daemon_issue_details(issue_type, port)} |\n")

                f.write("\n## Recommendations\n\n")
                recommendations = self._generate_recommendations(root_causes)
                for i, rec in enumerate(recommendations, 1):
                    f.write(f"{i}. **{rec['title']}**\n")
                    f.write(f"   {rec['description']}\n\n")

            self._generate_visualizations()
            return report_file

        except Exception as e:
            logger.error(f"Error generating report: {str(e)}")
            raise

    def _determine_root_causes(self):
        """Determine likely root causes of packet loss."""
        causes = []
        retransmit_rate = self.packet_stats["retransmissions"] / self.packet_stats["total_packets"] if \
        self.packet_stats["total_packets"] > 0 else 0
        if retransmit_rate > 0.05:
            causes.append({
                'cause': 'High TCP Retransmission Rate',
                'description': f'{retransmit_rate:.2%} retransmission rate indicates packet loss or congestion.',
                'severity': 'High' if retransmit_rate > 0.1 else 'Medium',
                'evidence': f'{self.packet_stats["retransmissions"]} retransmissions'
            })
        if self.packet_stats["zero_window"] > 10:
            causes.append({
                'cause': 'Receive Buffer Limitations',
                'description': 'Zero window events indicate receiver buffer issues.',
                'severity': 'High' if self.packet_stats["zero_window"] > 50 else 'Medium',
                'evidence': f'{self.packet_stats["zero_window"]} zero window events'
            })
        if self.netstat_data and self.netstat_data.get('issues'):
            for issue in self.netstat_data['issues']:
                causes.append({
                    'cause': f'TCP/IP Stack Issue: {issue["type"]}',
                    'description': f'Issue in TCP/IP stack: {issue["type"]}',
                    'severity': issue['severity'].capitalize(),
                    'evidence': f'Value: {issue["value"]}'
                })
        return causes

    def _get_issue_details(self, issue_type):
        """Get human-readable description for issue types."""
        descriptions = {
            'retransmission': 'Packets retransmitted due to loss or timeout',
            'out_of_order': 'Packets arriving out of sequence',
            'zero_window': 'Receiver buffer full, halting data transfer',
            'window_full': 'Sender window full, causing congestion',
            'reset': 'Connections abruptly terminated',
            'suspicious_gap': 'Large time gap indicating potential packet loss'
        }
        return descriptions.get(issue_type, 'Unknown issue')

    def _get_daemon_issue_details(self, issue_type, port):
        """Get details about daemon issues."""
        port_services = {
            22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 80: 'HTTP', 443: 'HTTPS'
        }
        service = port_services.get(port, f'Port {port}')
        descriptions = {
            'unexpected_reset': f'{service} daemon resetting connections unexpectedly',
            'no_response': f'{service} daemon not responding to UDP requests'
        }
        return descriptions.get(issue_type, f'Issue with {service} daemon')

    def _generate_recommendations(self, root_causes):
        """Generate recommendations based on root causes."""
        recommendations = []
        for cause in root_causes:
            if 'Retransmission' in cause['cause']:
                recommendations.append({
                    'title': 'Reduce Network Congestion',
                    'description': 'Check for duplex mismatches, faulty cables, or overloaded links.'
                })
            elif 'Buffer' in cause['cause']:
                recommendations.append({
                    'title': 'Increase Buffer Sizes',
                    'description': 'Adjust net.core.rmem_max and net.ipv4.tcp_rmem sysctl parameters.'
                })
        return recommendations

    def _generate_visualizations(self):
        """Generate visualizations of analysis results."""
        try:
            if self.tcp_issues:
                retransmits = [issue['timestamp'] for issue in self.tcp_issues if issue['type'] == 'retransmission']
                if retransmits:
                    min_time = min(retransmits)
                    rel_times = [(t - min_time) / 60 for t in retransmits]
                    plt.figure(figsize=(10, 4))
                    plt.hist(rel_times, bins=50)
                    plt.xlabel('Time (minutes)')
                    plt.ylabel('Retransmissions')
                    plt.title('TCP Retransmission Timeline')
                    plt.tight_layout()
                    plt.savefig(os.path.join(self.output_dir, 'retransmission_timeline.png'))
                    plt.close()
        except Exception as e:
            logger.warning(f"Error generating visualizations: {str(e)}")


def main():
    """Command-line interface for the NetworkAnalyzer."""
    parser = argparse.ArgumentParser(description="Network packet loss analysis tool")
    parser.add_argument("pcap_file", help="Path to the PCAP file")
    parser.add_argument("--interrupts", help="Path to /proc/interrupts file")
    parser.add_argument("--netstat", help="Path to netstat -s output file")
    parser.add_argument("--output-dir", help="Output directory for reports and visualizations")

    args = parser.parse_args()

    try:
        analyzer = NetworkAnalyzer(
            pcap_file=args.pcap_file,
            proc_interrupt_file=args.interrupts,
            netstat_file=args.netstat,
            output_dir=args.output_dir
        )
        output_dir = analyzer.analyze_pcap()
        print(f"Analysis complete. Results saved in: {output_dir}")
    except Exception as e:
        logger.error(f"Analysis failed: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
