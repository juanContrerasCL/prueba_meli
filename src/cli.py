# src/cli.py

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List

from .triage import triage_vulnerability


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="AI Triage - Validación estática asistida por IA para vulnerabilidades."
    )
    parser.add_argument(
        "--project-path",
        required=True,
        help="Ruta al proyecto que contiene el código fuente (por ejemplo: sample/app).",
    )
    parser.add_argument(
        "--findings-path",
        required=True,
        help="Ruta al archivo JSON con las vulnerabilidades detectadas (por ejemplo: sample/findings.json).",
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Ruta del archivo JSON de salida con el reporte de triage (por ejemplo: reports/report_sample.json).",
    )
    parser.add_argument(
        "--use-llm",
        action="store_true",
        help="Si se indica, intenta usar un modelo de IA (OpenAI) para refinar el triage.",
    )
    return parser.parse_args()


def load_vulnerabilities(findings_path: str) -> List[Dict[str, Any]]:
    """
    Carga el archivo JSON de findings y devuelve una lista de vulnerabilidades.
    Soporta varios formatos:
    - Objeto con clave 'vulnerabilities'
    - Objeto con clave 'findings'
    - Lista directa de vulnerabilidades
    """
    with open(findings_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    if isinstance(data, list):
        return data

    if "vulnerabilities" in data:
        return data["vulnerabilities"]

    if "findings" in data:
        return data["findings"]

    return []


def main() -> None:
    args = parse_args()

    project_path = args.project_path
    findings_path = args.findings_path
    output_path = args.output
    use_llm_requested = bool(args.use_llm)

    vulns = load_vulnerabilities(findings_path)

    results: List[Dict[str, Any]] = []
    for vuln in vulns:
        result = triage_vulnerability(
            project_path=project_path,
            vuln=vuln,
            use_llm=use_llm_requested,
        )
        results.append(result)

    # ¿Se llegó a usar IA en al menos una vulnerabilidad?
    llm_used_effective = any(r.get("llm_used") for r in results)

    report = {
        "input_findings": findings_path,
        "project_path": project_path,
        "use_llm_requested": use_llm_requested,
        "llm_used_effective": llm_used_effective,
        "results": results,
    }

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    print(f"✅ Reporte generado en {output_path}")

    if use_llm_requested:
        if llm_used_effective:
            print("   (La IA se usó efectivamente para apoyar el triage).")
        else:
            print("   (Se intentó usar IA, pero no estuvo disponible; se usaron solo reglas estáticas).")


if __name__ == "__main__":
    main()
