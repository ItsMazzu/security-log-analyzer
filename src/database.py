"""
Database Management

This module handles all SQLite database operations for storing and retrieving
authentication logs. Uses executemany() for efficient bulk inserts.
"""

import sqlite3
import os
from pathlib import Path
from typing import List, Dict


def get_db_path() -> str:
    """Get the path to the SQLite database file."""
    current_dir = Path(__file__).parent.parent
    db_dir = current_dir / "database"
    db_dir.mkdir(parents=True, exist_ok=True)
    return str(db_dir / "logs.db")


def initialize_database() -> None:
    """
    Create the auth_logs table if it doesn't exist.
    
    Table schema:
    - id: Auto-increment primary key
    - timestamp: ISO 8601 format datetime
    - username: User account name
    - ip_address: Source IP address
    - status: Authentication outcome (success/failed)
    """
    db_path = get_db_path()
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS auth_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            username TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            status TEXT NOT NULL
        )
    """)
    
    conn.commit()
    conn.close()


def store_logs_batch(logs: List[Dict]) -> None:
    """
    Store logs in the database using efficient batch insert.
    
    Uses executemany() instead of individual INSERT statements for better
    performance and cleaner code. Clears existing logs before inserting.
    
    Args:
        logs: List of log dictionaries to store
    """
    if not logs:
        return
    
    db_path = get_db_path()
    initialize_database()
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Clear existing logs
    cursor.execute("DELETE FROM auth_logs")
    
    # Prepare data tuples for batch insert
    log_tuples = [
        (log['timestamp'], log['username'], log['ip'], log['status'])
        for log in logs
    ]
    
    # Efficient batch insert
    cursor.executemany(
        "INSERT INTO auth_logs (timestamp, username, ip_address, status) VALUES (?, ?, ?, ?)",
        log_tuples
    )
    
    conn.commit()
    conn.close()


def get_all_logs() -> List[Dict]:
    """
    Retrieve all logs from the database.
    
    Returns:
        list: List of log dictionaries with all fields
    """
    db_path = get_db_path()
    
    if not os.path.exists(db_path):
        return []
    
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row  # Return rows as dictionaries
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM auth_logs ORDER BY timestamp ASC")
    rows = cursor.fetchall()
    
    conn.close()
    
    return [dict(row) for row in rows]


def get_logs_by_ip(ip_address: str) -> List[Dict]:
    """
    Retrieve all logs from a specific IP address.
    
    Args:
        ip_address: IP to filter by
        
    Returns:
        list: Logs from specified IP
    """
    db_path = get_db_path()
    
    if not os.path.exists(db_path):
        return []
    
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute(
        "SELECT * FROM auth_logs WHERE ip_address = ? ORDER BY timestamp ASC",
        (ip_address,)
    )
    rows = cursor.fetchall()
    
    conn.close()
    
    return [dict(row) for row in rows]
