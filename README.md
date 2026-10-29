# SIEM & Threat Detection Lab

A beginner-friendly, defensive Security Information and Event Management (SIEM) portfolio project.

## Features
- Ingests structured JSONL security events from a log file.
- Detects brute-force patterns: 5+ failed logins from one IP within 5 minutes.
- Detects a successful login after repeated failures from the same IP.
- Flags selected privileged-command events.
- Stores events and alerts in SQLite.
- Provides a Streamlit dashboard with filters and CSV export.
- Includes synthetic demo events and unit tests.



> **Scope:** This is a learning prototype, not a production SIEM. The included data is synthetic. Only collect or analyze logs from systems you own or are authorized to monitor.

## Requirements
- Python 3.11+
- Windows, Linux, or macOS

## Setup (Windows PowerShell)
1. Extract the ZIP file.
2. Open PowerShell in the `mini-siem-threat-detection-lab` folder.
3. Create a virtual environment:

   ```powershell
   py -m venv .venv
   ```
4. Activate it:

   ```powershell
   .\.venv\Scripts\Activate.ps1
   ```

   If PowerShell blocks activation, use Command Prompt instead:
   `.\.venv\Scripts\activate.bat`
5. Install dependencies:

   ```powershell
   python -m pip install -r requirements.txt
   ```
6. Generate the demo log file:

   ```powershell
   python generate_demo_logs.py
   ```
7. Ingest events and create alerts:

   ```powershell
   python siem.py ingest sample_logs/auth_events.jsonl
   ```
8. Launch the dashboard:

   ```powershell
   python -m streamlit run app.py
   ```
9. Your browser should open the local dashboard. Stop it with `Ctrl+C` in the terminal.

## Run tests
```powershell
python -m unittest discover -s tests -v
```

## Project structure
```text
mini-siem-threat-detection-lab/
├── app.py
├── siem.py
├── generate_demo_logs.py
├── requirements.txt
├── .gitignore
├── README.md
├── sample_logs/
│   └── auth_events.jsonl       # generated demo data
└── tests/
    └── test_detections.py
```

## Event format
Each line in the JSONL file is one event:

```json
{"timestamp":"2026-10-29T10:00:00Z","event_type":"failed_login","source_ip":"192.0.2.10","username":"analyst","details":"Invalid password"}
```

Supported `event_type` values in this demo:
- `failed_login`
- `successful_login`
- `privileged_command`

The IP range `192.0.2.0/24` is reserved for documentation and is used only for synthetic examples.

## Detection logic
1. **Brute-force pattern — High:** at least 5 failed logins from the same source IP within a rolling 5-minute window.
2. **Successful login after failures — High:** a successful login from an IP after at least 5 failures from that IP in the previous 5 minutes.
3. **Privileged command — Medium:** a `privileged_command` event is flagged for analyst review. This is not automatically proof of malicious activity.

Alerts are deduplicated by detection type, source IP, and time window to avoid repeated identical alerts during a single ingestion run.

## Important limitations
- Input events are structured JSONL, not raw Linux `auth.log` lines.
- The app processes the file when you run the ingest command; it does not yet tail logs continuously.
- Detection rules are illustrative and can produce false positives.
- Timestamps should be UTC ISO-8601 strings ending in `Z` or including an explicit timezone offset.
- SQLite is local storage; there is no authentication or multi-user access control in this prototype.

## Future improvements
- Parse native Linux `auth.log` and Windows Event Logs.
- Add Sigma-style configurable rules.
- Add alert acknowledgement and case notes.
- Add automated tests for malformed events and time boundaries.
- Add Docker support and GitHub Actions CI.

## Testing

The project includes 13 regression tests covering detection accuracy, event validation, time-window boundaries, duplicate ingestion, and alert deduplication.

### Run the tests

```bash
python -m pip install pytest
python -m pytest -v
```

### Test coverage

- Brute-force detection after five failed logins
- Five-minute time-window boundaries
- Separation of events by source IP
- Successful login following repeated failures
- Duplicate event ingestion and alert deduplication
- Invalid IP address and missing timezone validation
- Privileged command detection
- Sustained attacks and same-second event bursts