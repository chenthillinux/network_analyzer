NetworkAnalyzer
Description
NetworkAnalyzer is a Python-based tool for analyzing network packet captures (PCAP files) to identify the root causes of packet loss and other network performance issues. It leverages the pyshark library to process PCAP files and optionally analyzes system files (/proc/interrupts and netstat -s output) to provide insights into network and system-level problems. The tool generates a detailed Markdown report and visualizations (e.g., retransmission timelines) to help network engineers and administrators diagnose issues such as TCP retransmissions, DNS latency, and daemon-related problems.
Key Features

Packet Analysis: Detects TCP retransmissions, out-of-order packets, duplicates, zero window events, and more.
Latency Analysis: Measures TCP handshake, HTTP response, and DNS lookup latencies.
System Analysis: Examines /proc/interrupts for NIC interrupt imbalances and netstat -s for TCP/IP stack issues.
Root Cause Analysis: Identifies likely causes of packet loss with severity levels and evidence.
Reporting: Generates a comprehensive Markdown report and visualizations using matplotlib.
Performance: Supports batch processing and memory management for large PCAP files.
Command-Line Interface: Easy to use via command-line arguments.

Requirements

Python: 3.6 or higher
Dependencies:
pyshark: For packet capture analysis
matplotlib: For generating visualizations
numpy: For numerical computations


Optional:
tshark: For faster initial packet counting (part of Wireshark)


System Files (optional):
/proc/interrupts: Linux interrupt statistics
netstat -s output: TCP/IP stack statistics



Install dependencies using:
pip install pyshark matplotlib numpy

Install tshark (optional) on Debian/Ubuntu:
sudo apt-get install tshark

Installation

Clone the repository:
git clone https://github.com/chenthillinux/network_analyzer.git
cd NetworkAnalyzer


Install the required Python packages and OS should have tshark package .
Package         Version
--------------- -----------
appdirs         1.4.4
contourpy       1.3.3
cycler          0.12.1
fonttools       4.60.0
kiwisolver      1.4.9
lxml            6.0.1
matplotlib      3.10.6
numpy           2.3.3
packaging       25.0
pillow          11.3.0
pip             24.0
pyparsing       3.2.4
pyshark         0.6
python-dateutil 2.9.0.post0
six             1.17.0
termcolor       3.1.0


Ensure your PCAP file and optional system files (/proc/interrupts, netstat -s) are accessible.


Usage
The script can be run from the command line, providing a PCAP file and optional system files. The output is saved in a timestamped directory containing a Markdown report (packet_loss_analysis_report.md) and visualizations (e.g., retransmission_timeline.png).
Command-Line Syntax
python3 network_analyzer.py <pcap_file> [--interrupts <interrupts_file>] [--netstat <netstat_file>] [--output-dir <output_directory>]

Arguments

<pcap_file>: Path to the PCAP file (required).
--interrupts: Path to /proc/interrupts file (optional).
--netstat: Path to netstat -s output file (optional).
--output-dir: Custom output directory for reports and visualizations (optional; defaults to network_analysis_<timestamp>).

Example
Analyze a PCAP file with interrupt and netstat data:
python3 network_analyzer.py capture.pcap --interrupts interrupts.txt --netstat netstat.txt --output-dir output

This command:

Analyzes capture.pcap for network issues.
Processes interrupts.txt and netstat.txt for system-level insights.
Saves results in the output directory.

Output

Report: A Markdown file (packet_loss_analysis_report.md) with:
Root cause analysis summary
Packet statistics (e.g., retransmissions, duplicates)
TCP, DNS, and daemon issue details
Latency metrics (TCP handshakes, HTTP, DNS)
Recommendations for resolving issues


Visualizations: PNG files (e.g., retransmission_timeline.png) showing issue distributions and timelines.

How It Works

Initialization:

Validates input files and creates an output directory.
Sets up data structures for packet statistics, latency, and issues.


Packet Analysis:

Uses pyshark to process PCAP files, detecting TCP issues (retransmissions, zero window events), HTTP/DNS latencies, and daemon problems.
Tracks conversations and packet timing for jitter analysis.


System Analysis:

Parses /proc/interrupts to detect CPU interrupt imbalances.
Analyzes netstat -s output for TCP/IP stack issues (e.g., high retransmissions).


Root Cause Analysis:

Identifies issues like high retransmission rates, DNS errors, or interrupt imbalances.
Assigns severity levels (Low, Medium, High, Critical) based on thresholds.


Reporting and Visualization:

Generates a detailed Markdown report summarizing findings.
Creates visualizations (e.g., retransmission timeline) using matplotlib.



Example Output
For a sample PCAP file, the output directory might contain:
output/
├── packet_loss_analysis_report.md
├── retransmission_timeline.png

Sample Report Excerpt:
# Network Packet Loss Analysis Report

Generated on: 2025-09-18 15:51:00
PCAP File: capture.pcap

## Root Cause Analysis Summary

### Identified Issues
1. **High TCP Retransmission Rate**: 7.5% retransmission rate indicates packet loss or congestion.
   - Severity: Medium
   - Evidence: 750 retransmissions out of 10000 packets

## Packet Statistics
- Total Packets: 10000
- Retransmissions: 750
- Zero Window: 10

Limitations

Memory Usage: Large PCAP files may consume significant memory due to pyshark limitations.
UDP Analysis: Limited to basic request-response tracking; may need tuning for specific protocols.
System Files: Assumes Linux-style /proc/interrupts and netstat -s formats.
Visualizations: Currently generates a retransmission timeline; additional charts can be enabled.

Contributing
Contributions are welcome! To contribute:

Fork the repository.
Create a feature branch (git checkout -b feature/YourFeature).
Commit changes (git commit -m 'Add YourFeature').
Push to the branch (git push origin feature/YourFeature).
Open a pull request.

Please include tests and update documentation for new features.
License
This project is licensed under the MIT License. See the LICENSE file for details.
Contact
For questions or support, open an issue on GitHub or contact the maintainer at Chenthil.linux@gmail.com
