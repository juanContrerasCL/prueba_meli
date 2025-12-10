# src/severity.py

def default_severity(vuln_type: str, is_vulnerable: bool) -> str:
    """
    Regla simple de severidad en función del tipo de vulnerabilidad.
    """
    if not is_vulnerable:
        return "None"

    vuln_type = (vuln_type or "").lower()

    if "sql injection" in vuln_type:
        return "High"
    if "command injection" in vuln_type:
        return "High"
    if "ssrf" in vuln_type:
        return "Medium"

    return "Medium"
