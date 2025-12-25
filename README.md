# Security Log Analyzer

A Python-based security log analysis tool that parses authentication logs and detects
suspicious behavior such as brute-force login attempts using time-based detection rules.

This project simulates how real-world security teams analyze logs to identify malicious
activity based on behavioral patterns rather than single events.

---

## Features

- Parses raw authentication logs into structured security events
- Differentiates between successful and failed login attempts
- Detects brute-force attacks based on:
  - Number of failed login attempts
  - Time window analysis
- Generates clear, human-readable security alerts

---

## Detection Logic

The analyzer raises an alert when:

- An IP address generates **3 or more failed login attempts**
- Within a **30-second time window**

This approach reduces false positives and mirrors common SOC and SIEM detection rules.

---

## Example Output

=== Security Log Analyzer ===

Security Alerts:

Possible brute-force attack detected
Source IP: 192.168.1.15
Failed Attempts: 3
Time Window: 30 seconds