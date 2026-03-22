import re

SQL_PATTERNS = [
    r"(\bOR\b|\bAND\b)\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+['\"]?", # OR 1=1
    r"(\bUNION\b\s+(ALL\s+)?\bSELECT\b)", # UNION SELECT
    r"(--|#|\/\*)", # Comments
    r"(\bWAITFOR\b\s+DELAY\b|\bSLEEP\(\d+\))", # Time-based Blind
    r"(\bDROP\b|\bTRUNCATE\b|\bALTER\b|\bXP_CMDSHELL\b)", # Administrative/destructive
    r"(\bUPDATE\b|\bDELETE\b|\bINSERT\b).*;.*", # Stacked
    r"(['\"].*;.*)" # Multiple statements via quotes
]

def check_sqli(query):
    """
    Check if a query string contains any SQL injection patterns.
    Returns: (is_malicious, detected_pattern_list)
    """
    if not query:
        return False, []
    
    findings = []
    for pattern in SQL_PATTERNS:
        if re.search(pattern, query, re.IGNORECASE):
            findings.append(pattern)
            
    return len(findings) > 0, findings

def get_explanation(findings):
    """
    Returns a human-readable explanation for a resume/UI.
    """
    explanations = {
        r"(\bOR\b|\bAND\b)\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+['\"]?": "Logical Tautology (Bypass)",
        r"(\bUNION\b\s+(ALL\s+)?\bSELECT\b)": "Union-Based Injection (Exfiltration)",
        r"(--|#|\/\*)": "Comment Truncation Attack",
        r"(\bWAITFOR\b\s+DELAY\b|\bSLEEP\(\d+\))": "Time-Based Blind SQLi",
        r"(\bDROP\b|\bTRUNCATE\b|\bALTER\b|\bXP_CMDSHELL\b)": "Dangerous Admin Command",
        r"(\bUPDATE\b|\bDELETE\b|\bINSERT\b).*;.*": "Stacked Query Attack",
        r"(['\"].*;.*)": "Multiple Sequence Attack"
    }
    
    return [explanations.get(f, "Unknown SQL Pattern") for f in findings]
