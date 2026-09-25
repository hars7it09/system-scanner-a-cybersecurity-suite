# Security Event Logging System

## Overview
The System Security Scanner now includes a comprehensive logging system that automatically records all security events to a CSV file. This allows you to track system security changes over time and generate detailed reports.

## Features

### 1. Automatic Event Logging
The system automatically logs events from the following modules:
- **USB Devices**: When USB devices are connected or disconnected
- **Wi-Fi Network**: When WiFi network connections change
- **Ports**: Port scan activities (can be added)
- **Firewall**: Firewall events (ready for integration)
- **Malware**: Malware detection events (ready for integration)
- **Password Policy**: Password policy scans (ready for integration)

### 2. Log Entry Structure
Each log entry contains:
- **Date**: YYYY-MM-DD format
- **Time**: HH:MM:SS format
- **Module**: Which module generated the event (USB/WiFi/Port/Firewall/Malware/Password)
- **Event Description**: Detailed description of what happened
- **Risk Level**: Low, Medium, or High

### 3. Log Storage
- Logs are stored in `logs/security_events.csv`
- New entries are automatically appended
- CSV format allows easy viewing in Excel or other tools

## Usage

### View Logs
1. Open the application
2. Go to the **Security Logs** tab
3. View all logged security events in a formatted table
4. Logs are automatically loaded on startup

### Filter Logs
The Security Logs tab provides filtering options:
- **Filter by Module**: Select USB, WiFi, Port, etc. (All shows all events)
- **Filter by Risk Level**: Select Low, Medium, High (All shows all levels)
- Filters work together to show combined results
- Total count is updated based on filters

### Export Logs
1. Go to the **Security Logs** tab
2. Click **Export as CSV**
3. A new CSV file will be created in the `reports/` folder
4. File format: `logs_export_YYYYMMDD_HHMMSS.csv`

### Clear Logs
1. Go to the **Security Logs** tab
2. Click **Clear All Logs**
3. Confirm the prompt (this action cannot be undone)
4. All logs will be removed from the CSV file

### Include Logs in Reports
When you generate a report:
1. Go to the **Generate Report** tab
2. Click **Generate DOCX Report**
3. The generated report includes:
   - Summary of scans
   - Detailed results from all modules
   - **Security Event Logs** section with all recorded events in a table
   - File is saved as `reports/report_YYYYMMDD_HHMMSS.docx`

## Log Module API

### For Developers: Adding Logging to New Modules

To add logging to a new security module:

```python
from modules import log_storage

# Log a security event
log_storage.log_event(
    module_name="ModuleName",      # USB, WiFi, Port, etc.
    event_description="Event details",
    risk_level="Low"               # Low, Medium, or High
)
```

### Available Functions

```python
# Initialize/create the log file (called automatically on app start)
log_storage.init_log_file()

# Log a security event
success = log_storage.log_event(module_name, event_description, risk_level)

# Get all logs as list of dictionaries
all_logs = log_storage.get_all_logs()

# Get logs formatted for report generation
report_logs = log_storage.get_logs_for_report()

# Get count of log entries
count = log_storage.get_log_count()

# Clear all logs
success = log_storage.clear_logs()
```

## Examples

### USB Device Detection
```python
log_storage.log_event("USB", "External device detected: USB Disk (Kingston)", "Medium")
```

### WiFi Network Change
```python
log_storage.log_event("WiFi", "WiFi network changed to: HomeNetwork", "Medium")
```

### Malware Detection
```python
log_storage.log_event("Malware", "Suspicious process detected: unknown.exe", "High")
```

### Firewall Alert
```python
log_storage.log_event("Firewall", "Unauthorized port access attempt on port 445", "High")
```

## File Locations

- **Log file**: `logs/security_events.csv`
- **Log exports**: `reports/logs_export_*.csv`
- **Reports with logs**: `reports/report_*.docx`

## Data Storage

The CSV file structure:
```
Date,Time,Module,Event Description,Risk Level
2026-02-18,15:57:32,USB,Test USB device connected,High
2026-02-18,15:58:45,WiFi,WiFi network changed to: HomeWiFi,Medium
```

## Best Practices

1. **Regular Review**: Check logs regularly in the Security Logs tab
2. **Risk Assessment**: Pay attention to "High" and "Medium" risk events
3. **Backup Exports**: Periodically export and backup important logs
4. **Report Generation**: Include logs in weekly/monthly security reports
5. **Filtering**: Use filters to find specific event types

## Troubleshooting

### Logs not appearing in the dashboard?
- Click **Refresh** button to reload logs
- Check that `logs/` directory exists
- Verify CSV file has correct permissions

### CSV file corrupted?
- Click **Clear All Logs** to reset
- The system will create a new CSV file on next event

### Logs not being recorded?
- Verify the module is calling `log_storage.log_event()`
- Check that risk_level is one of: "Low", "Medium", "High"
- Check file permissions in the `logs/` directory

## Integration Summary

The logging system is fully integrated with:
- ✅ USB device monitoring
- ✅ WiFi connection tracking
- ✅ Security event logging
- ✅ Report generation
- ✅ Log viewing and filtering dashboard
- ✅ CSV export functionality

For manual event logging, use the `log_storage` module in any security module.
