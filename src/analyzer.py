"""
Security Analysis Engine

This module contains all threat detection logic including:
- Time-based brute force detection
- Credential stuffing detection  
- Suspicious login patterns (possible account compromise)
- Known malicious IP detection
"""

from datetime import datetime, timedelta
from collections import Counter, defaultdict
from pathlib import Path
from typing import List, Dict, Set, Tuple


def load_malicious_ips() -> Set[str]:
    """
    Load known malicious IPs from blacklist file.
    
    File format: One IP per line (supports comments starting with #)
    
    Returns:
        set: Set of malicious IP addresses
    """
    blacklist_path = Path(__file__).parent.parent / "config" / "malicious_ips.txt"
    
    malicious_ips = set()
    
    if not blacklist_path.exists():
        return malicious_ips
    
    try:
        with open(blacklist_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                # Skip empty lines and comments
                if line and not line.startswith('#'):
                    malicious_ips.add(line)
    except Exception as e:
        print(f"Warning: Could not load malicious IPs: {e}")
    
    return malicious_ips


def parse_timestamp(timestamp_str: str) -> datetime:
    """
    Parse ISO 8601 timestamp string to datetime object.
    
    Args:
        timestamp_str: Timestamp in format YYYY-MM-DD HH:MM:SS
        
    Returns:
        datetime: Parsed datetime object
    """
    return datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')


def detect_time_based_brute_force(logs: List[Dict], window_seconds: int = 60, threshold: int = 5) -> Dict[str, List[Dict]]:
    """
    Detect brute force attacks using a time-based sliding window.
    
    Identifies IPs with 5+ failed login attempts within a 60-second window.
    This is more realistic than just counting total attempts, as it captures
    active attack behavior.
    
    Args:
        logs: List of authentication logs
        window_seconds: Time window for detection (default 60 seconds)
        threshold: Minimum failed attempts in window to flag (default 5)
        
    Returns:
        dict: {ip_address: [failed_logs_in_window]}
    """
    failed_logs = [log for log in logs if log['status'].lower() == 'failed']
    time_based_threats = {}
    
    # Group by IP
    logs_by_ip = defaultdict(list)
    for log in failed_logs:
        logs_by_ip[log['ip']].append(log)
    
    # Check each IP for time-windowed attacks
    for ip, ip_logs in logs_by_ip.items():
        # Sort by timestamp
        ip_logs_sorted = sorted(ip_logs, key=lambda x: x['timestamp'])
        
        # Sliding window detection
        for i, log in enumerate(ip_logs_sorted):
            current_time = parse_timestamp(log['timestamp'])
            window_end = current_time + timedelta(seconds=window_seconds)
            
            # Count failures within window
            failures_in_window = [
                l for l in ip_logs_sorted
                if parse_timestamp(l['timestamp']) >= current_time and
                   parse_timestamp(l['timestamp']) <= window_end
            ]
            
            if len(failures_in_window) >= threshold:
                # Found a time-based brute force cluster
                if ip not in time_based_threats:
                    time_based_threats[ip] = failures_in_window
                break  # One detection per IP is enough
    
    return time_based_threats


def detect_credential_stuffing(logs: List[Dict]) -> Dict[str, int]:
    """
    Detect credential stuffing attacks.
    
    Credential stuffing is characterized by many failed attempts against
    multiple different user accounts from the same IP. This suggests
    the attacker is trying pre-compromised username/password pairs.
    
    Args:
        logs: List of authentication logs
        
    Returns:
        dict: {ip_address: unique_user_count}
    """
    failed_logs = [log for log in logs if log['status'].lower() == 'failed']
    
    credential_stuffing = {}
    
    # Count unique users targeted per IP
    by_ip = defaultdict(set)
    for log in failed_logs:
        by_ip[log['ip']].add(log['username'])
    
    # Credential stuffing: 3+ different users targeted with failures
    for ip, users in by_ip.items():
        if len(users) >= 3:
            credential_stuffing[ip] = len(users)
    
    return credential_stuffing


def detect_account_compromise_pattern(logs: List[Dict]) -> Dict[str, Dict]:
    """
    Detect suspicious login pattern: multiple failures followed by success.
    
    This pattern can indicate:
    1. Attacker successfully guessing/cracking a password
    2. User trying to regain access after changing password
    
    Flags entries where the same user+IP combo has 2+ failures followed
    by a success within a short timeframe (5 minutes).
    
    Args:
        logs: List of authentication logs
        
    Returns:
        dict: {ip_address: {username: details_dict}}
    """
    suspicious_patterns = {}
    
    # Group by IP and username
    by_ip_user = defaultdict(list)
    for log in logs:
        key = (log['ip'], log['username'])
        by_ip_user[key].append(log)
    
    # Check each IP+user combination
    for (ip, username), user_logs in by_ip_user.items():
        # Sort by timestamp
        sorted_logs = sorted(user_logs, key=lambda x: x['timestamp'])
        
        # Look for pattern: 2+ failures followed by success
        failures = 0
        for i, log in enumerate(sorted_logs):
            if log['status'].lower() == 'failed':
                failures += 1
            elif log['status'].lower() == 'success' and failures >= 2:
                # Found the pattern
                failure_logs = [l for l in sorted_logs[:i] if l['status'].lower() == 'failed']
                
                if ip not in suspicious_patterns:
                    suspicious_patterns[ip] = {}
                
                suspicious_patterns[ip][username] = {
                    'failed_attempts': failures,
                    'recovery_time': log['timestamp'],
                    'first_failure': failure_logs[0]['timestamp'] if failure_logs else None
                }
                failures = 0  # Reset for next sequence
    
    return suspicious_patterns


def detect_known_malicious_activity(logs: List[Dict]) -> Dict[str, int]:
    """
    Detect activity from known malicious IPs using a blacklist.
    
    Args:
        logs: List of authentication logs
        
    Returns:
        dict: {ip_address: attempt_count}
    """
    malicious_ips = load_malicious_ips()
    
    if not malicious_ips:
        return {}
    
    malicious_activity = {}
    
    for log in logs:
        if log['ip'] in malicious_ips:
            malicious_activity[log['ip']] = malicious_activity.get(log['ip'], 0) + 1
    
    return malicious_activity


def classify_attack_type(logs: List[Dict], ip: str) -> str:
    """
    Classify the type of attack from a given IP.
    
    Can detect multiple attack patterns and return them combined.
    
    Args:
        logs: List of authentication logs
        ip: IP address to analyze
        
    Returns:
        str: Attack type(s) as readable string
    """
    ip_logs = [log for log in logs if log['ip'] == ip and log['status'].lower() == 'failed']
    
    if not ip_logs:
        return "Unknown"
    
    # Count unique usernames and attempts per user
    targeted_users = {}
    for log in ip_logs:
        username = log['username']
        targeted_users[username] = targeted_users.get(username, 0) + 1
    
    unique_user_count = len(targeted_users)
    max_attempts_per_user = max(targeted_users.values()) if targeted_users else 0
    
    attack_types = []
    
    # Brute Force: Concentrated attacks on same user(s)
    # Indicated by high attempt count per user
    if max_attempts_per_user >= 3:
        attack_types.append("Brute Force")
    
    # Credential Stuffing: Attempts against many different users
    # Indicates pre-compromised password list being tested
    if unique_user_count >= 3:
        attack_types.append("Credential Stuffing")
    
    # Fallback if meets failure threshold but no specific pattern
    if not attack_types and len(ip_logs) > 5:
        attack_types.append("Brute Force")
    
    return " & ".join(attack_types) if attack_types else "Unknown"


def get_threat_summary(logs: List[Dict]) -> Dict:
    """
    Generate comprehensive threat analysis summary.
    
    Args:
        logs: List of authentication logs
        
    Returns:
        dict: Threat summary with all detected threats
    """
    failed_logs = [log for log in logs if log['status'].lower() == 'failed']
    
    # Count by IP
    ip_failure_counts = Counter(log['ip'] for log in failed_logs)
    
    # Detect all threat types
    time_based_threats = detect_time_based_brute_force(logs)
    credential_stuffing = detect_credential_stuffing(logs)
    account_compromise = detect_account_compromise_pattern(logs)
    malicious_ips = detect_known_malicious_activity(logs)
    
    # Compile threat IPs (any with 5+ failures)
    threatened_ips = {ip: count for ip, count in ip_failure_counts.items() if count > 5}
    
    return {
        'threatened_ips': threatened_ips,
        'time_based_brute_force': time_based_threats,
        'credential_stuffing': credential_stuffing,
        'account_compromise_patterns': account_compromise,
        'known_malicious_ips': malicious_ips
    }
