from pydantic_settings import BaseSettings
from pydantic import ConfigDict
from typing import Optional


class Settings(BaseSettings):
    """
    Configuración global del proyecto Mr.Robots.
    Los valores se leen automáticamente desde el archivo .env
    o desde variables de entorno del sistema.
    """

    model_config = ConfigDict(env_file=".env", env_file_encoding="utf-8")

    # ---------------------------------------------------------------------------
    # General
    # ---------------------------------------------------------------------------
    APP_NAME: str = "Mr.Robots — AI Governance Gateway"
    APP_VERSION: str = "0.1.0"
    DEBUG: bool = False

    # ---------------------------------------------------------------------------
    # API Keys de proveedores IA
    # ---------------------------------------------------------------------------
    OPENAI_API_KEY: Optional[str] = None
    GEMINI_API_KEY: Optional[str] = None
    CLAUDE_API_KEY: Optional[str] = None

    # ---------------------------------------------------------------------------
    # Modelo por defecto si el router no encuentra uno mejor
    # ---------------------------------------------------------------------------
    DEFAULT_MODEL: str = "gemini"

    # ---------------------------------------------------------------------------
    # Threat Detection — umbrales de riesgo
    # ---------------------------------------------------------------------------
    RISK_THRESHOLD_WARN: float = 0.4    # >= 0.4 → advertencia
    RISK_THRESHOLD_BLOCK: float = 0.7   # >= 0.7 → bloqueo

    # ---------------------------------------------------------------------------
    # Rutas internas
    # ---------------------------------------------------------------------------
    POLICIES_DIR: str = "policies"      # carpeta donde viven los JSON de políticas


# Instancia global — se importa desde cualquier módulo con:
# from config import settings
settings = Settings()