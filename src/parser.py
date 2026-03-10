"""
CSV Log Parser and Validator

This module handles loading authentication logs from CSV files and validating
their format using proper datetime parsing instead of regex patterns.
"""

import csv
import re
from datetime import datetime
from pathlib import Path
from typing import List, Dict


def get_csv_path() -> Path:
    """Get the path to the CSV file relative to this script."""
    current_dir = Path(__file__).parent.parent
    return current_dir / "data" / "auth_logs.csv"


def load_csv_logs() -> List[Dict]:
    """
    Load authentication logs from CSV file.
    
    Returns:
        list: List of dictionaries containing log entries with keys:
              - timestamp: ISO format datetime string
              - username: User account name
              - ip: IP address
              - status: 'success' or 'failed'
    """
    csv_path = get_csv_path()
    
    if not csv_path.exists():
        print(f"Error: CSV file not found at {csv_path}")
        return []
    
    logs = []
    try:
        with open(csv_path, 'r', encoding='utf-8') as file:
            reader = csv.DictReader(file)
            for row in reader:
                logs.append({
                    'timestamp': row['timestamp'],
                    'username': row['username'],
                    'ip': row['ip'],
                    'status': row['status']
                })
    except Exception as e:
        print(f"Error reading CSV: {e}")
    
    return logs


def validate_timestamp(timestamp_str: str) -> bool:
    """
    Validate timestamp using proper datetime parsing.
    
    Expected format: YYYY-MM-DD HH:MM:SS
    
    Args:
        timestamp_str: Timestamp string to validate
        
    Returns:
        bool: True if valid datetime, False otherwise
    """
    try:
        datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
        return True
    except ValueError:
        return False


def validate_ip_address(ip_str: str) -> bool:
    """
    Validate IP address using regex pattern.
    
    Supports both IPv4 and basic IPv6 detection patterns.
    
    Args:
        ip_str: IP address string to validate
        
    Returns:
        bool: True if valid IP format, False otherwise
    """
    ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    ipv6_pattern = r'^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$'
    
    return bool(re.match(ipv4_pattern, ip_str) or re.match(ipv6_pattern, ip_str))


def validate_logs(logs: List[Dict]) -> tuple[List[Dict], int]:
    """
    Validate all log entries for correct format and data types.
    
    Checks:
    - Timestamp is valid ISO 8601 datetime
    - IP address is valid IPv4 or IPv6
    - Status is either 'success' or 'failed'
    
    Args:
        logs: List of log dictionaries to validate
        
    Returns:
        tuple: (valid_logs list, invalid_count int)
    """
    valid_logs = []
    invalid_count = 0
    
    for log in logs:
        is_valid = True
        
        # Validate timestamp using proper datetime parsing
        if not validate_timestamp(log['timestamp']):
            invalid_count += 1
            is_valid = False
        
        # Validate IP address
        if not validate_ip_address(log['ip']):
            invalid_count += 1
            is_valid = False
        
        # Validate status field
        if log['status'].lower() not in ['success', 'failed']:
            invalid_count += 1
            is_valid = False
        
        if is_valid:
            valid_logs.append(log)
    
    return valid_logs, invalid_count
