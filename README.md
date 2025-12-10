# AI Triage – Validación estática asistida por IA

Herramienta de línea de comandos que toma los findings de un escáner estático (SAST) sobre un proyecto Python y genera un reporte de triage:

- Clasifica cada hallazgo como **True Positive / False Positive**.
- Asigna una **severidad**.
- Extrae **evidencia** (snippets de código).
- Opcionalmente utiliza un **LLM (OpenAI)** para refinar la decisión y enriquecer la explicación.

---

## Estructura del proyecto

```text
ai-triage/
├─ src/
│  ├─ cli.py            # CLI principal
│  ├─ triage.py         # Motor de triage (reglas + IA)
│  ├─ code_parser.py    # Utilidades para leer archivos y crear snippets
│  ├─ severity.py       # Mapeo de severidad por tipo de vulnerabilidad
│  └─ llm_client.py     # Cliente de LLM (OpenAI)
├─ sample/
│  ├─ app/
│  │  └─ sample.py      # Código de ejemplo con vulnerabilidades
│  └─ findings.json     # Findings de ejemplo simulando la salida de un SAST
├─ reports/
│  └─ report_sample_llm.json  # Ejemplo de salida (modo IA)
├─ README.md
└─ requirements.txt
```

---

## Requisitos

- Python 3.10+
- `pip`
- (Opcional, recomendado) entorno virtual (`venv`)

---

## Instalación

Desde la raíz del proyecto:

```bash
# Crear y activar entorno virtual (Windows PowerShell)
python -m venv venv
.\venv\Scripts\activate

# Instalar dependencias
pip install -r requirements.txt
```

---

## Configuración de IA (OpenAI)

La integración con IA es **opcional**, controlada por un flag.
Si quieres usarla, necesitas una API key de la plataforma de OpenAI.

En PowerShell (misma ventana donde se ve `(venv)`):

```powershell
$env:OPENAI_API_KEY="TU_API_KEY_DE_OPENAI"
```

Puedes comprobar que Python ve la variable con:

```powershell
python -c "import os; print(os.getenv('OPENAI_API_KEY'))"
```

Si no se configura la API key, o si hay un problema de red/billing, la herramienta **no falla**: simplemente cae en modo “solo reglas estáticas”.

---

## Uso

### 1. Modo solo reglas estáticas

Windows PowerShell:

```powershell
python -m src.cli ^
  --project-path sample/app ^
  --findings-path sample/findings.json ^
  --output reports/report_sample.json
```

Linux / macOS (bash):

```bash
python -m src.cli \
  --project-path sample/app \
  --findings-path sample/findings.json \
  --output reports/report_sample.json
```

### 2. Modo asistido por IA (OpenAI)

Windows PowerShell:

```powershell
python -m src.cli ^
  --project-path sample/app ^
  --findings-path sample/findings.json ^
  --output reports/report_sample_llm.json ^
  --use-llm
```

Linux / macOS:

```bash
python -m src.cli \
  --project-path sample/app \
  --findings-path sample/findings.json \
  --output reports/report_sample_llm.json \
  --use-llm
```

Diferencias:

- Sin `--use-llm` → **solo reglas estáticas**.
- Con `--use-llm` → reglas estáticas + revisión opcional con LLM (si está disponible).

---

## Formato de entrada

El archivo `findings.json` simula la salida de un SAST.
Ejemplo simplificado:

```json
{
  "vulnerabilities": [
    {
      "id": "vuln_01",
      "type": "SQL Injection",
      "file": "sample.py",
      "sink_line": 8,
      "source_line": 32,
      "message": "Posible SQL Injection en login_inseguro()"
    }
  ]
}
```

El loader soporta tres formatos:

- Objeto con clave `"vulnerabilities"`.
- Objeto con clave `"findings"`.
- Lista directa de vulnerabilidades.

---

## Formato de salida

El reporte generado (`report_sample*.json`) tiene la forma:

```json
{
  "input_findings": "sample/findings.json",
  "project_path": "sample/app",
  "use_llm_requested": true,
  "llm_used_effective": true,
  "results": [
    {
      "id": "vuln_01",
      "type": "SQL Injection",
      "message": "Posible SQL Injection en login_inseguro()",
      "status": "True Positive",
      "severity": "High",
      "explanation": "… explicación basada en reglas … IA: … explicación del LLM …",
      "evidence": [
        {
          "kind": "sink",
          "file": "sample.py",
          "line": 8,
          "snippet": "..."
        },
        {
          "kind": "source",
          "file": "sample.py",
          "line": 32,
          "snippet": "..."
        },
        {
          "kind": "llm",
          "file": "sample.py",
          "line": 8,
          "detail": "Detalle adicional aportado por el modelo (si aplica)"
        }
      ],
      "llm_used": true,
      "llm_status": "success"
    }
  ]
}
```

Campos importantes:

- `use_llm_requested`: si el usuario pasó o no el flag `--use-llm`.
- `llm_used_effective`: si, en al menos una vulnerabilidad, la IA se usó de verdad.
- En cada resultado:
  - `status`: `"True Positive"` / `"False Positive"`.
  - `severity`: severidad final (puede venir de reglas o del LLM).
  - `explanation`: texto combinado de reglas + IA (o de reglas únicamente).
  - `llm_used` y `llm_status`: reflejan el estado de la IA para esa vulnerabilidad.

---

## Lógica de triage

### Reglas estáticas

Las reglas viven en `triage.py` y se alimentan de los snippets generados por `code_parser.py`:

- **SQL Injection**
  - Marca como *seguro* si encuentra `execute(...)` con parámetros (`?`) en la query.
  - Marca como *vulnerable* si la consulta se construye con f-strings o concatenación de valores controlados por el usuario.
- **SSRF**
  - Si la petición va a un dominio fijo (`api.github.com`) y el usuario solo controla el path, se considera de bajo riesgo / falso positivo.
  - Si la URL de destino se construye de forma dinámica con datos del usuario hacia un host no fijo, se marca como posible SSRF.
- **Command Injection**
  - Busca usos de `os.system(...)`.
  - Considera vulnerable cuando el comando incluye interpolación/concatenación de datos del usuario (f-strings, `+`, etc.).

La severidad por defecto se calcula en `severity.py` a partir del tipo de vulnerabilidad y del resultado (`True/False Positive`).

### Capa de IA (LLM)

El módulo `llm_client.py` encapsula la integración con OpenAI:

- Usa el SDK oficial de `openai` y el modelo `gpt-4o-mini`.
- Recibe:
  - Tipo de vulnerabilidad.
  - Snippet del *sink*.
  - Snippet del *source*.
  - Resultado de las reglas (is_vulnerable + reason).
- Construye un prompt y pide al modelo un JSON con:
  - `is_vulnerable` (true/false)
  - `severity` (`None | Low | Medium | High | Critical`)
  - `reason` (explicación breve)
  - `evidence` (lista opcional de evidencias adicionales).

En `triage.py`, si `--use-llm` está activo:

1. Se ejecutan primero las **reglas estáticas**.
2. Se llama a `analyze_with_llm(...)`.
3. Si la IA responde correctamente:
   - Puede ajustar `is_vulnerable`.
   - Puede proponer una nueva `severity`.
   - Se añade su explicación al campo `explanation`.
   - Se añade su evidencia a la lista `evidence`.
4. Si la IA no está disponible (sin API key / error de red / billing):
   - No se rompe el flujo.
   - `llm_used = false`, `llm_status` describe el error.
   - Se mantiene el resultado de reglas estáticas.

---

## Decisiones de diseño

- **Separación de responsabilidades**
  - `cli.py`: interfaz de línea de comandos y formato de entrada/salida.
  - `triage.py`: lógica de negocio (reglas + combinación con IA).
  - `code_parser.py`: lectura de archivos y creación de snippets.
  - `llm_client.py`: dependencia con OpenAI aislada, fácil de cambiar de modelo/proveedor.
- **Degradación elegante**
  - El sistema siempre funciona con reglas estáticas.
  - La IA es un plus opcional; si no está disponible, no rompe la ejecución.
- **Extensibilidad**
  - Es sencillo añadir nuevos tipos de vulnerabilidad (`analyze_*` en `triage.py`).
  - Se pueden ajustar reglas de severidad en `severity.py`.
  - Se puede conectar otro LLM usando la misma interfaz de `llm_client.py`.

---

## Posibles mejoras futuras

- Añadir tests unitarios para las funciones de reglas (`analyze_sql_injection`, `analyze_ssrf`, etc.).
- Soportar más lenguajes o tipos de vulnerabilidad.
- Exportar el reporte también en formato HTML o Markdown.
- Integrar esta herramienta como paso automático dentro de un pipeline CI/CD.

---



