"""
Security Log Analyzer - Main Entry Point

A professional Security Operations Center (SOC) style log analysis tool
that detects and classifies authentication-based security threats.

Features:
- Time-based brute force detection
- Credential stuffing identification
- Account compromise pattern detection
- Known malicious IP blacklist support
- Professional terminal UI with Rich library

Modules:
- parser.py: CSV loading and validation with datetime parsing
- analyzer.py: Threat detection and classification logic
- database.py: SQLite operations with batch inserts
- ui.py: Terminal display with Rich formatting

Usage:
    python main.py
"""

from rich.console import Console
import parser
import analyzer
import database
import ui

console = Console()


def main():
    """
    Main application flow.
    
    Orchestrates the complete security analysis workflow:
    1. Load authentication logs from CSV
    2. Validate log entries with proper datetime parsing
    3. Store logs in SQLite database using batch inserts
    4. Perform comprehensive threat analysis
    5. Display results with Rich formatting
    """
    console.clear()
    
    # ============ PHASE 1: INITIALIZE ============
    ui.display_header()
    
    # ============ PHASE 2: LOAD LOGS ============
    ui.display_status("Loading logs...", "info")
    logs = parser.load_csv_logs()
    
    if not logs:
        ui.display_status("No logs found to process.", "error")
        return
    
    ui.display_status(f"✓ Loaded {len(logs)} logs", "success")
    
    # ============ PHASE 3: VALIDATE LOGS ============
    ui.display_status("Validating logs...", "info")
    valid_logs, invalid_count = parser.validate_logs(logs)
    
    if invalid_count > 0:
        ui.display_status(f"Warning: {invalid_count} invalid log entries skipped", "warning")
    
    ui.display_status(f"✓ {len(valid_logs)} logs validated\n", "success")
    
    # ============ PHASE 4: STORE IN DATABASE ============
    ui.display_status("Storing logs in database...", "info")
    database.store_logs_batch(valid_logs)
    ui.display_status("✓ Logs stored\n", "success")
    
    # ============ PHASE 5: DISPLAY LOGS ============
    console.print()
    ui.display_logs_table(valid_logs)
    console.print()
    
    # ============ PHASE 6: SUMMARY STATISTICS ============
    ui.display_summary(valid_logs)
    console.print()
    
    # ============ PHASE 7: THREAT ANALYSIS ============
    threat_summary = analyzer.get_threat_summary(valid_logs)
    ui.display_threats(threat_summary, valid_logs)


if __name__ == "__main__":
    main()
