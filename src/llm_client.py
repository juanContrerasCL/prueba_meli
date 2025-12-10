import json
import os
from typing import Any, Dict

from openai import OpenAI


class LLMNotConfiguredError(Exception):
    """Se lanza cuando no hay API key o cliente de LLM configurado."""


def _get_client() -> OpenAI:
    """
    Devuelve un cliente de OpenAI usando la variable de entorno OPENAI_API_KEY.
    """
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise LLMNotConfiguredError(
            "No se encontró la variable de entorno OPENAI_API_KEY."
        )
    return OpenAI(api_key=api_key)


def analyze_with_llm(
    vuln_type: str,
    sink_snippet: str,
    source_snippet: str,
    rule_based: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Envía al modelo de IA la información de la vulnerabilidad y devuelve
    una evaluación en formato JSON estructurado.

    La respuesta esperada del modelo es un JSON con el siguiente esquema:

    {
      "is_vulnerable": true/false,
      "severity": "None|Low|Medium|High|Critical",
      "reason": "Explicación corta",
      "evidence": [
        {"line": 27, "detail": "Descripción opcional de la evidencia"}
      ]
    }
    """
    client = _get_client()

    system_prompt = (
        "Eres un asistente experto en seguridad de aplicaciones. "
        "Te enviaré fragmentos de código y el resultado de un análisis estático "
        "muy sencillo (reglas). Debes devolver una decisión en JSON válido, "
        "sin texto adicional."
    )

    user_prompt = f"""
Tipo de vulnerabilidad reportada: {vuln_type}

Resultado de reglas estáticas:
- is_vulnerable: {rule_based.get("is_vulnerable")}
- reason: {rule_based.get("reason")}

Fragmento de código (sink):
\"\"\"
{sink_snippet}
\"\"\"

Fragmento de código (source):
\"\"\"
{source_snippet}
\"\"\"

TAREA:
1. Indica si consideras que la vulnerabilidad es REAL (`is_vulnerable` true/false).
2. Propón una severidad (`severity`) en ['None','Low','Medium','High','Critical'].
3. Explica brevemente el motivo en `reason`.
4. Si lo consideras útil, añade una lista `evidence` con objetos de la forma
   {{ "line": <numero_de_linea_o_null>, "detail": "texto corto" }}.

RESPONDE ÚNICAMENTE con un JSON, sin texto adicional.
"""

    completion = client.chat.completions.create(
        model="gpt-4o-mini",  # modelo general, rápido y barato :contentReference[oaicite:1]{index=1}
        response_format={"type": "json_object"},  # Forzamos JSON válido :contentReference[oaicite:2]{index=2}
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        temperature=0,
    )

    content = completion.choices[0].message.content

    try:
        data = json.loads(content)
    except json.JSONDecodeError as exc:
        # Si algo sale mal, devolvemos un resultado mínimo que respete las reglas
        return {
            "is_vulnerable": rule_based.get("is_vulnerable"),
            "severity": None,
            "reason": f"No se pudo parsear JSON del LLM ({exc}); se mantiene la decisión de reglas.",
            "evidence": [],
        }

    # Normalizamos campos
    return {
        "is_vulnerable": data.get("is_vulnerable", rule_based.get("is_vulnerable")),
        "severity": data.get("severity"),
        "reason": data.get("reason", ""),
        "evidence": data.get("evidence") or [],
    }
