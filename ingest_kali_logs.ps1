
$Project = "$HOME\OneDrive\Documents\Desktop\SIEM project\mini-siem-threat-detection-lab"
$LogFile = "$HOME\OneDrive\Documents\Desktop\kali shared\siem_ssh_events.jsonl"
$Python = (Get-Command python).Source

Set-Location $Project

if (Test-Path $LogFile) {
    & $Python "$Project\siem.py" ingest $LogFile
}
