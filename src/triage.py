from typing import Dict, Any

from .code_parser import read_file_lines, get_snippet
from .severity import default_severity
from .llm_client import analyze_with_llm, LLMNotConfiguredError


def analyze_sql_injection(sink_snippet: str) -> Dict[str, Any]:
    """
    Regla muy simple para SQL Injection en Python.

    Consideramos vulnerable si:
    - Hay un execute() en el snippet
    - Y la query se construye concatenando variables o usando f-strings
    Consideramos seguro si:
    - La query usa parámetros de la forma "?" en execute().
    """
    snippet_lower = sink_snippet.lower()

    if "execute(" in snippet_lower and "?" in snippet_lower:
        return {
            "is_vulnerable": False,
            "reason": "La consulta usa parámetros (?) en cur.execute, lo que mitiga SQL Injection.",
        }

    if "execute(" in snippet_lower and (
        "f\"" in sink_snippet
        or "{username}" in sink_snippet
        or "{password}" in sink_snippet
        or "+" in sink_snippet
    ):
        return {
            "is_vulnerable": True,
            "reason": "La consulta SQL se construye concatenando/interpolando parámetros de usuario directamente en el string.",
        }

    return {
        "is_vulnerable": False,
        "reason": "No se encontró construcción insegura de la consulta en el snippet analizado.",
    }


def analyze_ssrf(sink_snippet: str) -> Dict[str, Any]:
    """
    Regla simple para SSRF.

    - Si se usa requests.get() hacia api.github.com consideramos bajo riesgo (False Positive).
    - Si la URL contiene partes controladas por el usuario hacia un dominio no fijo, marcamos como posible SSRF.
    """
    snippet_lower = sink_snippet.lower()

    if "requests.get" not in snippet_lower:
        return {
            "is_vulnerable": False,
            "reason": "No se encontraron llamadas a requests.get en el snippet.",
        }

    if "api.github.com" in snippet_lower:
        return {
            "is_vulnerable": False,
            "reason": "La petición se hace a un dominio fijo (api.github.com); el usuario solo controla el path.",
        }

    return {
        "is_vulnerable": True,
        "reason": "La URL de destino se construye dinámicamente con datos potencialmente controlados por el usuario (posible SSRF).",
    }


def analyze_command_injection(sink_snippet: str) -> Dict[str, Any]:
    """
    Regla simple para Command Injection.

    - Si encontramos os.system() y el comando incluye valores interpolados o concatenados, lo marcamos como vulnerable.
    """
    snippet_lower = sink_snippet.lower()

    if "os.system" not in snippet_lower:
        return {
            "is_vulnerable": False,
            "reason": "No se encontraron llamadas a os.system en el snippet.",
        }

    if "f\"" in sink_snippet or "{" in sink_snippet or "+" in sink_snippet:
        return {
            "is_vulnerable": True,
            "reason": "Se usa os.system con un comando que incluye directamente valores interpolados (f-strings/concatenación) controlados por el usuario.",
        }

    return {
        "is_vulnerable": True,
        "reason": "Se usa os.system con un comando dinámico; se considera potencial Command Injection.",
    }


def triage_vulnerability(
    project_path: str,
    vuln: Dict[str, Any],
    use_llm: bool = False,
) -> Dict[str, Any]:
    """
    Función principal de triage para una vulnerabilidad.
    Lee el código, extrae snippets, aplica reglas y opcionalmente consulta un LLM.
    Además indica si la IA se llegó a usar efectivamente o no.
    """
    filename = vuln.get("file")
    sink_line = vuln.get("sink_line")
    source_line = vuln.get("source_line")
    vuln_type = vuln.get("type", "")

    # 1) Leemos el archivo fuente
    lines = read_file_lines(project_path, filename)

    # 2) Snippets alrededor del sink y del source
    sink_snippet = get_snippet(lines, sink_line, window=5) if sink_line else ""
    source_snippet = get_snippet(lines, source_line, window=5) if source_line else ""

    # 3) Análisis por reglas estáticas
    vuln_type_lower = (vuln_type or "").lower()

    if "sql injection" in vuln_type_lower:
        rule_analysis = analyze_sql_injection(sink_snippet)
    elif "ssrf" in vuln_type_lower:
        rule_analysis = analyze_ssrf(sink_snippet)
    elif "command injection" in vuln_type_lower:
        rule_analysis = analyze_command_injection(sink_snippet)
    else:
        rule_analysis = {
            "is_vulnerable": False,
            "reason": f"Tipo de vulnerabilidad no soportado aún: {vuln_type}",
        }

    is_vulnerable = bool(rule_analysis.get("is_vulnerable"))
    reason = rule_analysis.get("reason", "")

    llm_evidence = []
    llm_note = ""
    llm_used = False          # <-- ¿la IA se usó de verdad?
    llm_status = "skipped"    # <-- por defecto: no se pidió
    llm_severity_override = None

    # 4) (Opcional) Revisión con IA
    if use_llm:
        llm_status = "requested"  # se intentará usar
        try:
            llm_result = analyze_with_llm(
                vuln_type=vuln_type,
                sink_snippet=sink_snippet,
                source_snippet=source_snippet,
                rule_based=rule_analysis,
            )
            llm_used = True
            llm_status = "success"

            # Actualizamos decisión si el LLM discrepa
            if "is_vulnerable" in llm_result:
                is_vulnerable = bool(llm_result["is_vulnerable"])

            llm_reason = llm_result.get("reason") or ""
            if llm_reason:
                llm_note = f" IA: {llm_reason}"

            llm_severity_override = llm_result.get("severity")
            llm_evidence = llm_result.get("evidence") or []

        except LLMNotConfiguredError as exc:
            llm_used = False
            llm_status = f"not_configured: {exc}"
            llm_note = f" IA no configurada: {exc}"
        except Exception as exc:  # errores de red, etc.
            llm_used = False
            llm_status = f"error: {exc}"
            llm_note = f" Error al invocar IA: {exc}"

    # 5) Severidad final
    severity = default_severity(vuln_type, is_vulnerable)
    if llm_used and llm_severity_override and is_vulnerable:
        # Si el LLM propone severidad y la vulnerabilidad sigue siendo positiva,
        # respetamos su propuesta
        severity = llm_severity_override

    status = "True Positive" if is_vulnerable else "False Positive"
    explanation = (reason + llm_note).strip()

    # Evidencia: sink + source
    evidence = [
        {
            "kind": "sink",
            "file": filename,
            "line": sink_line,
            "snippet": sink_snippet,
        },
        {
            "kind": "source",
            "file": filename,
            "line": source_line,
            "snippet": source_snippet,
        },
    ]

    # Añadimos evidencia del LLM (si regresó algo)
    for ev in llm_evidence:
        evidence.append(
            {
                "kind": "llm",
                "file": filename,
                "line": ev.get("line"),
                "detail": ev.get("detail"),
            }
        )

    return {
        "id": vuln.get("id"),
        "type": vuln_type,
        "message": vuln.get("message"),
        "status": status,
        "severity": severity,
        "explanation": explanation,
        "evidence": evidence,
        "llm_used": llm_used,       # <-- se usó IA en esta vuln
        "llm_status": llm_status,   # <-- éxito / error / no configurada
    }