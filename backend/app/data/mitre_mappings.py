# alert_signature -> (technique_id, technique_name, base_severity 0-100)
MITRE_LOOKUP = {
    "failed_login_burst": ("T1110", "Brute Force", 60),
    "outbound_beacon_c2": ("T1071", "Application Layer Protocol (C2)", 85),
    "suspicious_powershell": ("T1059.001", "PowerShell", 75),
    "lateral_movement_smb": ("T1021.002", "SMB/Windows Admin Shares", 80),
    "data_exfil_large_transfer": ("T1041", "Exfiltration Over C2 Channel", 90),
    "unmapped": ("T1059", "Command and Scripting Interpreter (generic)", 40),
}
