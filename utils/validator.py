import re

def sanitize_input(user_input):
    """
    Sanitize input by removing common SQL injection special characters.
    This is a basic security layer (defense in depth).
    """
    if not user_input:
        return ""
    
    # Remove --, #, /*, */, etc.
    sanitized = re.sub(r"(--|#|\/\*|\*\/|;)", "", str(user_input))
    # Escape single/double quotes (basic)
    sanitized = sanitized.replace("'", "''").replace('"', '\\"')
    
    return sanitized.strip()

def validate_length(user_input, max_len=100):
    """
    Strict length validation. Simple but effective for many buffer/injection cases.
    """
    return len(str(user_input)) <= max_len

def validate_email(email):
    """
    Format validation.
    """
    pattern = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(pattern, email) is not None
