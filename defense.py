import logging
import re
import ipaddress

# Configure logger
import sys
logger = logging.getLogger("DefenseLayer")
logger.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

# File Handler
file_handler = logging.FileHandler("defense_alerts.log")
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

# Stdout Handler
stream_handler = logging.StreamHandler(sys.stdout)
stream_handler.setFormatter(formatter)
logger.addHandler(stream_handler)

# Malicious patterns (Injection/SQLi/XSS/Noise)
MALICIOUS_PATTERNS = [
    r"<script", r"</script>", r";", r"'", r'"', r"--", r"%", r"\{", r"\}", r"<>", r"\0"
]

def evaluate_input_robustness(ip, device, browser, hour):
    """
    Evaluates inputs for adversarial patterns and anomalies.
    Returns: (severity: str, is_suspicious: bool, reasons: list[str])
    Severity levels: 'ALLOW', 'MFA', 'BLOCK'
    """
    reasons = []
    severity = "ALLOW"
    is_suspicious = False
    
    # 1. Hour check
    if not isinstance(hour, int) or hour < 0 or hour > 23:
        reasons.append(f"Invalid hour: {hour}")
        severity = "BLOCK"
        
    # 2. IP check
    if ip:
        if len(ip) > 45: # IPv6 max length is 45, though 39 is standard
            reasons.append(f"IP address too long: {len(ip)} chars")
            severity = "BLOCK"
        else:
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                reasons.append(f"Malformed IP address: {ip}")
                severity = "BLOCK"
                
    # 3. Device and Browser length checks
    device_str = str(device) if device else ""
    browser_str = str(browser) if browser else ""
    
    if len(device_str) > 150:
        reasons.append(f"Extremely long device string: {len(device_str)} chars")
        severity = "BLOCK"
        
    if len(browser_str) > 150:
        reasons.append(f"Extremely long browser string: {len(browser_str)} chars")
        severity = "BLOCK"
        
    # 4. Malicious injection pattern checks
    for pattern in MALICIOUS_PATTERNS:
        if re.search(pattern, device_str, re.IGNORECASE):
            reasons.append(f"Obvious injection pattern found in device string")
            severity = "BLOCK"
            break
        if re.search(pattern, browser_str, re.IGNORECASE):
            reasons.append(f"Obvious injection pattern found in browser string")
            severity = "BLOCK"
            break
            
    # If already blocked, no need to check MFA rules
    if severity == "BLOCK":
        is_suspicious = True
        logger.warning(f"[BLOCK] Suspicious inputs detected: {reasons}")
        return severity, is_suspicious, reasons
        
    # 5. MFA (Suspicious but Plausible) checks
    # Repeated characters (e.g. "aaaaa")
    if re.search(r"(.)\1{4,}", device_str) or re.search(r"(.)\1{4,}", browser_str):
        reasons.append("Repeated characters detected in device/browser")
        severity = "MFA"
        
    # Excessive whitespace
    if re.search(r"\s{4,}", device_str) or re.search(r"\s{4,}", browser_str):
        reasons.append("Excessive whitespace detected in device/browser")
        severity = "MFA"

    # Unusual characters but not purely malicious (e.g., lots of non-ascii without being malicious)
    # Check if > 50% of the string is non-alphanumeric (simple heuristic)
    def is_mostly_non_alphanum(s):
        if not s: return False
        non_alnum = sum(1 for c in s if not c.isalnum() and not c.isspace())
        return non_alnum / len(s) > 0.5

    if is_mostly_non_alphanum(device_str):
        reasons.append("Device string is mostly non-alphanumeric characters")
        severity = "MFA"
        
    if is_mostly_non_alphanum(browser_str):
        reasons.append("Browser string is mostly non-alphanumeric characters")
        severity = "MFA"

    if severity == "MFA":
        is_suspicious = True
        logger.info(f"[MFA] Moderately abnormal inputs detected: {reasons}")
    else:
        logger.info(f"[ALLOW] Inputs passed robustness checks. (IP={ip}, Hour={hour})")
        
    return severity, is_suspicious, reasons
