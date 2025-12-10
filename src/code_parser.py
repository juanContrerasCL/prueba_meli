# src/code_parser.py

from pathlib import Path
from typing import List


def read_file_lines(project_path: str, filename: str) -> List[str]:
    """
    Lee un archivo de código y devuelve la lista de líneas.
    """
    full_path = Path(project_path) / filename
    with full_path.open("r", encoding="utf-8") as f:
        return f.readlines()


def get_snippet(lines: List[str], center_line: int, window: int = 5) -> str:
    """
    Devuelve un snippet de texto alrededor de center_line (± window líneas),
    incluyendo los números de línea al inicio para referencia.
    """
    if center_line is None:
        return ""

    total_lines = len(lines)
    start = max(1, center_line - window)
    end = min(total_lines, center_line + window)

    snippet_lines = []
    for i in range(start, end + 1):
        # i es 1-based; índice de lista es 0-based
        snippet_lines.append(f"{i:4}: {lines[i - 1].rstrip()}")

    return "\n".join(snippet_lines)
