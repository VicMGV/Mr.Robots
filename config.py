from pydantic_settings import BaseSettings
from pydantic import ConfigDict
from typing import Optional


class Settings(BaseSettings):

    model_config = ConfigDict(env_file=".env", env_file_encoding="utf-8")

    APP_NAME: str = "Mr.Robots — AI Governance Gateway"
    APP_VERSION: str = "0.1.0"
    DEBUG: bool = False


    OPENAI_API_KEY: Optional[str] = None
    GEMINI_API_KEY: Optional[str] = None
    CLAUDE_API_KEY: Optional[str] = None
    GROQ_API_KEY: Optional[str] = None


    DEFAULT_MODEL: str = "groq"

    RISK_THRESHOLD_WARN: float = 0.4   
    RISK_THRESHOLD_BLOCK: float = 0.7   


    POLICIES_DIR: str = "policies"      



settings = Settings()