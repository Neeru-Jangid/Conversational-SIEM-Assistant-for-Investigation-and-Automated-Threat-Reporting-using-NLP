"""
config/settings.py

Central configuration using Pydantic. All modules import from here.
Never scatter os.getenv() calls across files — keep them here.
"""

from pydantic import BaseModel
from dotenv import load_dotenv
import os

load_dotenv()


class Settings(BaseModel):
    # Elasticsearch
    es_host: str = os.getenv("ES_HOST", "localhost")
    es_port: int = int(os.getenv("ES_PORT", "9200"))
    es_user: str = os.getenv("ES_USER", "admin")
    es_password: str = os.getenv("ES_PASSWORD", "admin")
    es_verify_certs: bool = os.getenv("ES_VERIFY_CERTS", "false").lower() == "true"
    es_index: str = os.getenv("ES_INDEX", "wazuh-alerts-demo")

    # Ollama
    ollama_host: str = os.getenv("OLLAMA_HOST", "http://localhost:11434")
    ollama_model: str = os.getenv("OLLAMA_MODEL", "llama3.1:8b")
    ollama_classifier_model: str = os.getenv("OLLAMA_CLASSIFIER_MODEL", "qwen2.5:7b")
    ollama_embed_model: str = os.getenv("OLLAMA_EMBED_MODEL", "nomic-embed-text")
    # Set to false to use ollama_model for everything (single-model mode)
    use_classifier_model: bool = os.getenv("USE_CLASSIFIER_MODEL", "true").lower() == "true"

    # ChromaDB
    chroma_path: str = os.getenv("CHROMA_PATH", "./rag/chroma_store")

    # App
    debug: bool = os.getenv("APP_DEBUG", "true").lower() == "true"
    max_results: int = int(os.getenv("MAX_RESULTS", "100"))
    context_window: int = int(os.getenv("CONTEXT_WINDOW", "10"))
    dsl_mode: str = os.getenv("DSL_MODE", "hybrid")  # llm | template | hybrid

    @property
    def es_url(self) -> str:
        return f"https://{self.es_host}:{self.es_port}"


# Singleton — import this everywhere
settings = Settings()