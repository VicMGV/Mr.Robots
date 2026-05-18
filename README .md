# 🤖 Mr.Robots — AI Governance Gateway

Gateway centralizado de gobernanza para modelos de inteligencia artificial. Cada solicitud pasa por un pipeline de detección de amenazas, aplicación de políticas, enrutamiento de modelos y validación de respuestas antes de llegar al usuario.

---

## 📋 Tabla de Contenidos

- [Descripción del Proyecto](#descripción-del-proyecto)
- [Arquitectura](#arquitectura)
- [Requisitos Previos](#requisitos-previos)
- [Variables de Entorno](#variables-de-entorno)
- [Instalación y Ejecución](#instalación-y-ejecución)
  - [Opción A — Docker (recomendado)](#opción-a--docker-recomendado)
  - [Opción B — Ejecución local](#opción-b--ejecución-local)
- [Proveedores de IA Soportados](#proveedores-de-ia-soportados)
- [Pipeline de Detección de Amenazas](#pipeline-de-detección-de-amenazas)
- [Políticas por Departamento](#políticas-por-departamento)
- [Endpoints de la API](#endpoints-de-la-api)
- [Dashboard Web](#dashboard-web)
- [Ejecutar Tests](#ejecutar-tests)
- [Estructura del Proyecto](#estructura-del-proyecto)

---

## Descripción del Proyecto

**Mr.Robots** es un gateway de gobernanza para IA que actúa como intermediario entre los usuarios y los modelos de lenguaje. Su función principal es garantizar que todas las interacciones con IA sean seguras, auditables y conformes a las políticas organizacionales.

### Funcionalidades principales

- **Detección de amenazas en 3 capas** (reglas, heurísticas y LLM local)
- **Motor de políticas** configurable por departamento (HR, Finance, Engineering)
- **Enrutamiento dinámico** entre múltiples proveedores de IA
- **Validación de respuestas** antes de entregarlas al usuario
- **Audit log completo** en formato JSONL
- **Dashboard web** para monitoreo en tiempo real

---

## Arquitectura

```
Usuario / Cliente
       │
       ▼
┌─────────────────────────────────────────────────────┐
│                  FastAPI Gateway                    │
│  ┌─────────────┐  ┌────────────┐  ┌─────────────┐  │
│  │  Threat     │→ │  Policy    │→ │   Model     │  │
│  │  Detector   │  │  Engine    │  │   Router    │  │
│  │ (3 layers)  │  │ (per dept) │  │             │  │
│  └─────────────┘  └────────────┘  └──────┬──────┘  │
│                                          │          │
│  ┌───────────────────────────────────────┘          │
│  ▼                                                  │
│  ┌─────────────┐  ┌─────────────┐                   │
│  │  Response   │  │   Audit     │                   │
│  │  Validator  │  │   Logger    │                   │
│  └─────────────┘  └─────────────┘                   │
└─────────────────────────────────────────────────────┘
         │            │             │
         ▼            ▼             ▼
       Groq         Gemini        Claude
     (Llama 3.3)  (Gemini API)  (Anthropic)
```

---

## Requisitos Previos

### Software necesario

| Herramienta | Versión mínima | Notas |
|-------------|---------------|-------|
| Python | 3.11+ | Requerido para ejecución local |
| Docker | 24+ | Requerido para ejecución con Docker |
| Docker Compose | 2.x | Incluido en Docker Desktop |
| pip | 23+ | Para instalar dependencias |

### Opcional — Layer 3 LLM local (Ollama)

Si deseas activar la capa 3 de detección de amenazas (clasificación mediante LLM local), necesitas instalar Ollama:

1. Descarga desde [https://ollama.com/download](https://ollama.com/download)
2. Descarga el modelo `phi`:
   ```bash
   ollama pull phi
   ollama serve
   ```

> ⚠️ Sin Ollama, el sistema funciona normalmente usando solo las capas 1 y 2 (reglas + heurísticas). Para activar la capa 3, usa `ThreatDetector(use_llm=True)` en `gateway/main.py`.

---

## Variables de Entorno

Crea un archivo `.env` en la raíz del proyecto `Mr.Robots/` con el siguiente contenido:

```env
# ─── Modelos de IA (configura al menos uno) ────────────────────────────────
GROQ_API_KEY=tu_groq_api_key_aqui
GEMINI_API_KEY=tu_gemini_api_key_aqui
CLAUDE_API_KEY=tu_claude_api_key_aqui
OPENAI_API_KEY=tu_openai_api_key_aqui

# ─── Configuración general ─────────────────────────────────────────────────
DEFAULT_MODEL=groq       # Proveedor por defecto: groq | gemini | claude | openai
DEBUG=false              # true para logs detallados
```

### ¿Dónde conseguir las API Keys?

| Proveedor | URL | Notas |
|-----------|-----|-------|
| **Groq** | https://console.groq.com | Tier gratuito generoso — **recomendado para empezar** |
| **Gemini** | https://aistudio.google.com | Requiere cuenta Google |
| **Claude** | https://console.anthropic.com | Requiere cuenta Anthropic |
| **OpenAI** | https://platform.openai.com | Requiere cuenta y tarjeta |

> 💡 **Solo necesitas configurar al menos un proveedor.** Groq es el más rápido para empezar por su tier gratuito.

---

## Instalación y Ejecución

### Opción A — Docker (recomendado)

Es la forma más sencilla. No requiere instalar Python ni dependencias manualmente.

```bash
# 1. Clona o descomprime el proyecto
cd Mr.Robots

# 2. Crea el archivo .env con tus API keys
cp .env.example .env   # o crea el .env manualmente

# 3. Construye y levanta el contenedor
docker compose up --build

# El servidor estará disponible en:
# http://localhost:8000
```

El Dockerfile hace una construcción multi-stage que:
- Instala todas las dependencias de Python
- Pre-descarga el modelo ML de HuggingFace (`cross-encoder/nli-distilroberta-base`)
- Monta un volumen para persistir los logs de auditoría
- Expone el puerto `8000`

---

### Opción B — Ejecución local

```bash
# 1. Entra al directorio del proyecto
cd Mr.Robots

# 2. (Opcional) Crea un entorno virtual
python -m venv venv
source venv/bin/activate       # Linux/Mac
venv\Scripts\activate          # Windows

# 3. Instala las dependencias
pip install -r requirements.txt

# 4. Crea tu archivo .env
# (ver sección Variables de Entorno)

# 5. Levanta el servidor
uvicorn gateway.main:app --host 0.0.0.0 --port 8000 --reload

# El servidor estará disponible en:
# http://localhost:8000
```

> ⚠️ En la primera ejecución, el modelo ML de HuggingFace se descargará automáticamente (~250 MB). Esto puede tardar unos minutos según tu conexión.

---

## Proveedores de IA Soportados

| Proveedor | Modelo usado | Adapter |
|-----------|-------------|---------|
| **Groq** | `llama-3.3-70b-versatile` | `providers/groq_adapter.py` |
| **Gemini** | Gemini API | `providers/gemini_adapter.py` |
| **Claude** | Anthropic API | `providers/claude_adapter.py` |

El sistema selecciona el proveedor con base en la variable `DEFAULT_MODEL` del `.env` y las políticas del departamento del usuario.

---

## Pipeline de Detección de Amenazas

Cada prompt pasa por **3 capas de análisis** antes de llegar al modelo de IA:

### Capa 1 — Reglas (Regex + Keywords)
Detecta patrones de ataque conocidos:
- Prompt injection: `"ignore all previous instructions"`
- Jailbreak: `"DAN mode"`, `"disable safety filters"`
- Exfiltración de datos: `"export confidential data"`, `"dump the database"`
- Comportamiento inseguro: `"create malware"`, `"synthesize drugs"`

### Capa 2 — Heurísticas
Analiza el comportamiento del prompt:
- Prompts excesivamente largos (ocultamiento de instrucciones)
- Obfuscación en Base64 / hexadecimal
- Acumulación sospechosa de keywords
- Baja diversidad de palabras (ataques por repetición)
- Intentos de inyección multi-idioma

### Capa 3 — LLM Local (Ollama + phi) _(opcional)_
Clasifica prompts ambiguos que las capas 1 y 2 no detectan con claridad. Corre completamente local, sin costo ni API key.

### Acciones según score de riesgo

| Risk Score | Acción |
|------------|--------|
| 0.00 – 0.34 | `allow` — se procesa normalmente |
| 0.35 – 0.64 | `warn` — se procesa con advertencia |
| 0.65 – 0.84 | `block` — se rechaza la solicitud |
| 0.85 – 1.00 | `escalate` — se bloquea y escala para revisión |

---

## Políticas por Departamento

Las políticas se configuran como archivos JSON en la carpeta `policies/`. Controlan qué modelos puede usar cada departamento y qué contenido está restringido.

### Departamentos disponibles

| Departamento | Modelos permitidos | Restricciones |
|--------------|-------------------|---------------|
| `engineering` | gemini, claude, openai, groq, internal | No exportar credenciales |
| `hr` | gemini, internal | Sin acceso externo; no mencionar datos personales |
| `finance` | (ver `policies/finance.json`) | Políticas financieras |

### Agregar un nuevo departamento

Crea un archivo `policies/nuevo_depto.json`:

```json
{
  "department": "nuevo_depto",
  "allowed_models": ["groq", "gemini"],
  "blocked_actions": ["external_export"],
  "blocked_keywords": ["palabra_restringida"],
  "max_prompt_length": 5000,
  "allow_external_providers": true,
  "notes": "Descripción del departamento."
}
```

---

## Endpoints de la API

Una vez el servidor esté corriendo, puedes ver la documentación interactiva en:

- **Swagger UI:** http://localhost:8000/docs
- **ReDoc:** http://localhost:8000/redoc

### Principales rutas

| Método | Ruta | Descripción |
|--------|------|-------------|
| `POST` | `/v1/chat` | Envía un prompt al gateway |
| `GET` | `/health` | Health check del servicio |
| `GET` | `/` | Dashboard web |

### Ejemplo de solicitud

```bash
curl -X POST http://localhost:8000/v1/chat \
  -H "Content-Type: application/json" \
  -H "X-API-Key: tu_api_key" \
  -d '{
    "prompt": "¿Cuál es la capital de Francia?",
    "department": "engineering",
    "model": "groq"
  }'
```

### Ejemplo de respuesta

```json
{
  "request_id": "abc-123",
  "status": "success",
  "action": "allow",
  "risk_score": 0.02,
  "threat_type": null,
  "model_used": "groq",
  "response": "La capital de Francia es París.",
  "audit_logged": true
}
```

---

## Dashboard Web

El proyecto incluye un dashboard web accesible en `http://localhost:8000`.

Permite:
- Enviar prompts y ver la respuesta en tiempo real
- Visualizar el risk score y la acción tomada por el gateway
- Consultar el log de auditoría

Los archivos estáticos del dashboard están en `static/` (HTML, CSS, JS).

---

## Ejecutar Tests

```bash
# Instala dependencias de testing (si no las tienes)
pip install pytest pytest-asyncio

# Ejecutar todos los tests
pytest test/ -v

# Ejecutar solo los tests del threat detector
pytest test/test_threat_detector.py -v

# Ejecutar solo los tests del pipeline completo
pytest test/test_pipeline.py -v
```

---

## Estructura del Proyecto

```
Mr.Robots/
├── .env                     # Variables de entorno (NO subir a git)
├── .dockerignore
├── config.py                # Configuración global (Pydantic Settings)
├── docker-compose.yml       # Orquestación Docker
├── Dockerfile               # Build multi-stage
├── requirements.txt         # Dependencias Python
│
├── gateway/                 # Núcleo del gateway
│   ├── main.py              # FastAPI app + pipeline principal
│   ├── models.py            # Modelos Pydantic (Request/Response)
│   ├── threat_detector.py   # Detección de amenazas (3 capas)
│   ├── policy_engine.py     # Motor de políticas por departamento
│   ├── model_router.py      # Enrutamiento entre proveedores
│   ├── response_validator.py# Validación de respuestas del modelo
│   └── audit_logger.py      # Logging de auditoría (JSONL)
│
├── providers/               # Adaptadores para cada proveedor de IA
│   ├── base.py              # Clase base abstracta
│   ├── groq_adapter.py      # Adaptador para Groq (Llama 3.3)
│   ├── gemini_adapter.py    # Adaptador para Google Gemini
│   └── claude_adapter.py    # Adaptador para Anthropic Claude
│
├── ml/                      # Clasificador ML local
│   └── classifier.py        # Zero-shot classification (HuggingFace)
│
├── policies/                # Políticas JSON por departamento
│   ├── engineering.json
│   ├── finance.json
│   └── hr.json
│
├── static/                  # Dashboard web
│   ├── index.html
│   ├── app.js
│   └── style.css
│
├── logs/                    # Audit logs (generados en runtime)
│   └── audit.jsonl
│
└── test/                    # Tests
    ├── test_threat_detector.py
    └── test_pipeline.py
```

---

## Notas de Seguridad

- **Nunca subas el archivo `.env` a un repositorio público.** Contiene tus API keys.
- El archivo `.env` ya está listado en `.dockerignore` para evitar que se incluya en la imagen Docker.
- Los logs de auditoría (`logs/audit.jsonl`) pueden contener prompts sensibles — mantenlos protegidos.
- La autenticación del gateway usa un header `X-API-Key`. Configura un valor seguro en producción.

---

## Dependencias principales

| Paquete | Uso |
|---------|-----|
| `fastapi` | Framework web principal |
| `uvicorn` | Servidor ASGI |
| `pydantic` + `pydantic-settings` | Validación de datos y configuración |
| `httpx` | Cliente HTTP async para llamadas a proveedores |
| `transformers` + `torch` | Clasificador ML local (HuggingFace) |
| `python-dotenv` | Carga de variables de entorno |
| `python-jose` | Autenticación / seguridad |
| `pytest` + `pytest-asyncio` | Testing |
