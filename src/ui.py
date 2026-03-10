"""
User Interface Layer

This module contains all Rich-based terminal output formatting.
Handles tables, panels, and colored alerts for the security analysis.
"""

from rich.table import Table
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from typing import List, Dict

console = Console()


def get_ip_timeline(logs: List[Dict], ip: str) -> tuple:
    """
    Get first and last timestamp for a specific IP's failed attempts.
    
    Args:
        logs: List of authentication logs
        ip: IP address to analyze
        
    Returns:
        tuple: (first_timestamp, last_timestamp, count)
    """
    ip_failures = [log for log in logs if log['ip'] == ip and log['status'].lower() == 'failed']
    
    if not ip_failures:
        return None, None, 0
    
    ip_failures_sorted = sorted(ip_failures, key=lambda x: x['timestamp'])
    
    return (
        ip_failures_sorted[0]['timestamp'],
        ip_failures_sorted[-1]['timestamp'],
        len(ip_failures)
    )


def display_header() -> None:
    """Display the application header with title and description."""
    header = Text()
    header.append("[SECURITY LOG ANALYZER]\n", style="bold cyan")
    header.append("Professional Security Monitoring System", style="dim white")
    console.print(Panel(header, expand=False, border_style="cyan"))


def display_logs_table(logs: List[Dict]) -> None:
    """
    Display authentication logs in a formatted table.
    
    Shows: Timestamp, Username, IP Address, Status
    Status is color-coded (green for success, red for failed).
    
    Args:
        logs: List of authentication log dictionaries
    """
    table = Table(
        title="[bold]Authentication Logs[/bold]",
        show_header=True,
        header_style="bold cyan"
    )
    
    table.add_column("Timestamp", style="white")
    table.add_column("Username", style="cyan")
    table.add_column("IP Address", style="magenta")
    table.add_column("Status", style="green")
    
    for log in logs:
        status_style = "green" if log['status'].lower() == 'success' else "red"
        table.add_row(
            log['timestamp'],
            log['username'],
            log['ip'],
            f"[{status_style}]{log['status']}[/{status_style}]"
        )
    
    console.print(table)


def display_summary(logs: List[Dict]) -> None:
    """
    Display authentication statistics summary.
    
    Shows: Total logs, successful/failed counts, unique users and IPs.
    
    Args:
        logs: List of authentication log dictionaries
    """
    total_logs = len(logs)
    successful = sum(1 for log in logs if log['status'].lower() == 'success')
    failed = sum(1 for log in logs if log['status'].lower() == 'failed')
    unique_users = len(set(log['username'] for log in logs))
    unique_ips = len(set(log['ip'] for log in logs))
    
    summary_text = f"""
    [bold cyan]Total Logs:[/bold cyan] {total_logs}
    [bold green]Successful:[/bold green] {successful}
    [bold red]Failed:[/bold red] {failed}
    [bold magenta]Unique Users:[/bold magenta] {unique_users}
    [bold yellow]Unique IPs:[/bold yellow] {unique_ips}
    """
    
    console.print(Panel(
        summary_text.strip(),
        title="[bold]Summary[/bold]",
        border_style="cyan",
        expand=False
    ))


def display_threats(threat_summary: Dict, logs: List[Dict]) -> None:
    """
    Display all detected threats with classification.
    
    Shows multiple threat categories:
    - Standard brute force and credential stuffing attacks
    - Time-based attack clusters
    - Possible account compromise patterns
    - Known malicious IP activity
    
    Args:
        threat_summary: Dictionary from analyzer.get_threat_summary()
        logs: Original list of logs for context
    """
    all_threats = threat_summary['threatened_ips']
    
    if not all_threats:
        console.print(Panel(
            "[green]No threats detected[/green]",
            title="[bold]Security Status[/bold]",
            border_style="green"
        ))
        return
    
    # Import here to avoid circular dependency
    import analyzer
    
    threat_text = ""
    
    # Display standard threats
    for ip, count in sorted(all_threats.items(), key=lambda x: x[1], reverse=True):
        attack_type = analyzer.classify_attack_type(logs, ip)
        first_ts, last_ts, _ = get_ip_timeline(logs, ip)
        
        threat_text += f"[bold red][ALERT][/bold red] {first_ts} -> {last_ts}\n"
        threat_text += f"[bold red]Source IP:[/bold red] {ip}\n"
        threat_text += f"[bold red]Activity:[/bold red] {count} failed login attempts\n"
        threat_text += f"[bold red]Classification:[/bold red] {attack_type} Attack\n"
        threat_text += "\n"
    
    console.print(Panel(
        threat_text.strip(),
        title="[bold red]Threats Detected[/bold red]",
        border_style="red",
        expand=False
    ))
    
    # Display additional threat patterns if found
    if threat_summary['account_compromise_patterns']:
        console.print()
        display_account_compromise_alerts(threat_summary['account_compromise_patterns'])
    
    if threat_summary['known_malicious_ips']:
        console.print()
        display_malicious_ip_alerts(threat_summary['known_malicious_ips'], logs)


def display_account_compromise_alerts(compromise_patterns: Dict) -> None:
    """
    Display possible account compromise alerts.
    
    Flags suspicious pattern: multiple failed attempts followed by successful login.
    
    Args:
        compromise_patterns: Dictionary from analyzer.detect_account_compromise_pattern()
    """
    alert_text = ""
    
    for ip, user_details in compromise_patterns.items():
        for username, details in user_details.items():
            first_failure = details['first_failure']
            recovery_time = details['recovery_time']
            failed_count = details['failed_attempts']
            
            alert_text += f"[bold yellow][SUSPICIOUS][/bold yellow] {recovery_time}\n"
            alert_text += f"[bold yellow]Source IP:[/bold yellow] {ip}\n"
            alert_text += f"[bold yellow]Target Account:[/bold yellow] {username}\n"
            alert_text += f"[bold yellow]Pattern:[/bold yellow] {failed_count} failures -> successful login\n"
            alert_text += f"[bold yellow]Attack Window:[/bold yellow] {first_failure} to {recovery_time}\n"
            alert_text += "\n"
    
    if alert_text:
        console.print(Panel(
            alert_text.strip(),
            title="[bold yellow]Possible Account Compromise[/bold yellow]",
            border_style="yellow",
            expand=False
        ))


def display_malicious_ip_alerts(malicious_ips: Dict, logs: List[Dict] = None) -> None:
    """
    Display known malicious IP activity alerts.
    
    Args:
        malicious_ips: Dictionary from analyzer.detect_known_malicious_activity()
        logs: Optional log list for timing information
    """
    alert_text = ""
    
    for ip, count in sorted(malicious_ips.items(), key=lambda x: x[1], reverse=True):
        if logs:
            first_ts, last_ts, _ = get_ip_timeline(logs, ip)
            alert_text += f"[bold red][BLACKLIST][/bold red] {first_ts} -> {last_ts}\n"
            alert_text += f"[bold red]Malicious IP:[/bold red] {ip}\n"
            alert_text += f"[bold red]Activity:[/bold red] {count} attempts from known threat source\n"
            alert_text += "\n"
        else:
            alert_text += f"[bold red][BLACKLIST] {ip}[/bold red] - {count} attempts\n"
    
    if alert_text:
        console.print(Panel(
            alert_text.strip(),
            title="[bold red]Known Malicious IP Activity[/bold red]",
            border_style="red",
            expand=False
        ))


def display_status(message: str, status_type: str = "info") -> None:
    """
    Display a status message.
    
    Args:
        message: Message to display
        status_type: 'info', 'success', 'warning', or 'error'
    """
    colors = {
        'info': 'cyan',
        'success': 'green',
        'warning': 'yellow',
        'error': 'red'
    }
    color = colors.get(status_type, 'white')
    console.print(f"[{color}]{message}[/{color}]")
