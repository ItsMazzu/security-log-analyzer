# Security Log Analyzer

A professional Security Operations Center (SOC) style authentication log analysis tool that detects and classifies security threats in real-time.

## Overview

This project demonstrates realistic security monitoring by analyzing authentication logs to identify:
- **Brute Force Attacks**: Multiple login attempts against the same account
- **Credential Stuffing**: Attempts against multiple accounts from the same IP
- **Account Compromise Patterns**: Suspicious failed-then-successful login sequences
- **Known Malicious IPs**: Detection of activity from blacklisted IP addresses

### Key Features

✓ **Time-based brute force detection** (5+ failures within 60 seconds)
✓ **Advanced threat classification** (can detect multiple attack patterns)
✓ **Account compromise pattern recognition** (failures followed by success)
✓ **IP blacklist support** for known malicious addresses
✓ **Professional terminal UI** with Rich formatting
✓ **Batch database operations** using `executemany()`
✓ **Proper datetime validation** instead of regex patterns
✓ **Modular, learner-friendly architecture**

---

## Project Structure

```
security-log-analyzer/
├── src/
│   ├── __init__.py          # Package initialization
│   ├── main.py              # Application entry point & orchestration
│   ├── parser.py            # CSV loading and validation
│   ├── analyzer.py          # Threat detection logic
│   ├── database.py          # SQLite operations
│   └── ui.py                # Rich terminal formatting
├── config/
│   └── malicious_ips.txt    # IP blacklist
├── data/
│   └── auth_logs.csv        # Input log data
├── database/
│   └── logs.db              # SQLite database (auto-created)
├── run.py                   # Entry point script
├── requirements.txt         # Dependencies
└── README.md               # This file
```

---

## Installation

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Add Malicious IPs (Optional)

Edit `config/malicious_ips.txt` to add known malicious IP addresses:

```
# One IP per line, comments start with #
192.168.1.254
10.0.0.1
203.0.113.45
```

---

## Usage

### Run the Analyzer

```bash
python run.py
```

### Output Sections

**1. Authentication Logs Table**
- Displays all parsed log entries
- Color-coded status (green = success, red = failed)

**2. Summary Statistics**
- Total logs, successful/failed counts
- Number of unique users and IP addresses

**3. Threats Detected**
- List of threatening IPs with attack classification
- Shows attempt counts and attack types

**4. Possible Account Compromise**
- Flags suspicious patterns: multiple failures followed by success
- Useful for detecting password crack success or account takeover

**5. Known Malicious IP Activity**
- Highlights activity from blacklisted IPs

---

## How It Works

### Phase 1: Load & Parse
**Module**: `parser.py`
- Loads CSV authentication logs
- Validates timestamps using `datetime.strptime()` (ensures actual valid dates)
- Validates IP addresses with regex patterns
- Returns clean, validated log list

### Phase 2: Store in Database
**Module**: `database.py`
- Uses `cursor.executemany()` for efficient batch inserts
- Single operation for 63 logs instead of 63 separate queries
- Stores in SQLite with indexed timestamp and IP fields

### Phase 3: Threat Analysis
**Module**: `analyzer.py`

#### Time-Based Brute Force Detection
```python
# Detects 5+ failures within 60-second window
# More realistic than just counting total attempts
```

#### Credential Stuffing Recognition
```python
# Identifies attempts against 3+ different users from same IP
# Suggests pre-compromised password list being tested
```

#### Account Compromise Pattern
```python
# Flags: 2+ failed login attempts followed by successful login
# Could indicate password cracker success or user regaining access
```

#### Known Malicious IP Detection
```python
# Compares all attempt IPs against config/malicious_ips.txt
# Highlights any matches
```

### Phase 4: Display Results
**Module**: `ui.py`
- Uses Rich library for professional terminal output
- Color-coded panels for different threat categories
- Readable tables for log display
- Status indicators and statistics

---

## Code Examples

### Example 1: Attack Classification

```python
# The analyzer automatically classifies attack types
# Single attack type:
"Potential Brute Force Attack"

# Multiple attack patterns detected:
"Potential Brute Force & Credential Stuffing Attack"
```

### Example 2: Custom Threat Detection

Add new detection logic to `analyzer.py`:

```python
def detect_unusual_hours(logs):
    """Detect login attempts during unusual hours (e.g., 2-4 AM)"""
    unusual = {}
    for log in logs:
        time = parse_timestamp(log['timestamp']).hour
        if time in [2, 3, 4]:  # 2-4 AM
            ip = log['ip']
            unusual[ip] = unusual.get(ip, 0) + 1
    return unusual
```

Then add to `get_threat_summary()` and display in `ui.py`.

### Example 3: Extend the Blacklist

```properties
# config/malicious_ips.txt
# Known Botnet IPs
192.0.2.1
198.51.100.5

# Tor Exit Nodes  
203.0.113.10
203.0.113.11
```

---

## Learning Outcomes

This project teaches:

1. **Real Security Concepts**
   - Different attack patterns and their characteristics
   - How SOCs detect threats
   - Practical log analysis

2. **Python Best Practices**
   - Modular code architecture
   - Type hints for clarity
   - Proper error handling
   - Datetime manipulation (not regex!)

3. **Database Operations**
   - SQLite batch inserts (`executemany`)
   - Efficient data storage
   - Indexed queries

4. **Terminal User Interfaces**
   - Rich library for professional output
   - Color-coded alerts
   - Formatted tables and panels

5. **Security Analysis**
   - Log parsing and validation
   - Pattern recognition
   - Threat classification

---

## Testing

### Run with Sample Data

The included `data/auth_logs.csv` contains 63 sample entries with:
- Successful logins (19)
- Failed attempts (44)
- 3 different brute force attack patterns
- Account compromise attempts
- Credential stuffing attempts

### Modify Logs for Custom Tests

Edit `data/auth_logs.csv` to add your own test scenarios:

```csv
timestamp,username,ip,status
2026-03-01 12:00:00,admin,192.168.1.1,failed
2026-03-01 12:00:05,admin,192.168.1.1,failed
2026-03-01 12:00:10,admin,192.168.1.1,failed
```

---

## Performance Notes

- **Batch Insert Speed**: ~63 logs stored in single operation (vs 63 separate)
- **Detection Algorithms**: O(n) time complexity for all analyzers
- **Memory Usage**: Minimal - all data stored in simple dictionaries

---

## Future Enhancements

Possible additions without over-engineering:

- [ ] Repeat offender tracking across multiple runs
- [ ] CSV export of detected threats
- [ ] Alert severity levels (low/medium/high/critical)
- [ ] Rate limiting statistics
- [ ] Failed login recovery time analysis

---

## Project Status

**Current Version – March 2026**

Key features and improvements:

- ✓ Modular architecture for maintainability
- ✓ Proper datetime validation
- ✓ Batch database operations
- ✓ Enhanced threat detection logic
- ✓ Account compromise pattern recognition
- ✓ IP blacklist support
- ✓ Clean code organization
- ✓ Project documentation

---

## Technologies

- **Python 3.8+**
- **Rich 13.7.0** - Terminal formatting
- **SQLite** - Database storage
- **Standard Library** - datetime, csv, collections, pathlib

---

## Author

Security Analysis Learning Project

## License

Educational use only

