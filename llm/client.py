"""
llm/client.py

Single point of contact for Ollama.
All other modules call this — never call Ollama directly elsewhere.

On RTX 4060 + 16GB RAM with Llama 3.1 8B Q4_K_M:
  - Model load time: ~10s first call, instant after
  - Intent extraction: ~1-3s
  - DSL generation: ~3-8s
  - Narrative summary: ~5-15s
"""

import json
import os
import sys
import requests
from typing import Generator

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config.settings import settings


class OllamaClient:
    """
    Thin wrapper around Ollama REST API.
    Handles errors, retries, and streaming.
    """

    def __init__(self):
        self.base_url = settings.ollama_host
        self.model = settings.ollama_model
        self.timeout = 120  # Llama 3.1 8B can be slower on complex prompts

    def chat(
        self,
        messages: list[dict],
        temperature: float = 0.1,
        max_tokens: int = 1000,
        json_mode: bool = False,
        system: str = None,
    ) -> str:
        """
        Send a chat completion request to Ollama.

        Args:
            messages:    List of {"role": str, "content": str}
            temperature: Sampling temperature (0.0-1.0)
                         0.0-0.2 for structured output (DSL, JSON)
                         0.3-0.5 for narrative summaries
            max_tokens:  Maximum tokens to generate
            json_mode:   Enforce JSON output (Ollama format param)
            system:      System prompt (prepended to messages)

        Returns:
            Response text as string

        On failure, returns error string starting with "ERROR:"
        """
        full_messages = []
        if system:
            full_messages.append({"role": "system", "content": system})
        full_messages.extend(messages)

        payload = {
            "model": self.model,
            "messages": full_messages,
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_predict": max_tokens,
                "num_ctx": 8192,      # Llama 3.1 8B supports up to 128k, 8k is safe
                "num_gpu": 35,        # number of layers on GPU — covers all 32 for 8B
            },
        }

        if json_mode:
            payload["format"] = "json"

        try:
            response = requests.post(
                f"{self.base_url}/api/chat",
                json=payload,
                timeout=self.timeout,
            )
            response.raise_for_status()
            return response.json()["message"]["content"].strip()

        except requests.exceptions.ConnectionError:
            return "ERROR: Cannot connect to Ollama. Is it running? Try: ollama serve"
        except requests.exceptions.Timeout:
            return "ERROR: Ollama request timed out. Model may still be loading."
        except Exception as e:
            return f"ERROR: {e}"

    def generate(self, prompt: str, temperature: float = 0.2, max_tokens: int = 500) -> str:
        """Simple single-prompt generate (non-chat)."""
        try:
            response = requests.post(
                f"{self.base_url}/api/generate",
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False,
                    "options": {
                        "temperature": temperature,
                        "num_predict": max_tokens,
                        "num_gpu": 35,
                    },
                },
                timeout=self.timeout,
            )
            response.raise_for_status()
            return response.json().get("response", "").strip()
        except Exception as e:
            return f"ERROR: {e}"

    def embed(self, text: str) -> list[float]:
        """Get embedding vector for text using nomic-embed-text."""
        try:
            # Try new endpoint first (/api/embed), fall back to old (/api/embeddings)
            response = requests.post(
                f"{self.base_url}/api/embed",
                json={"model": settings.ollama_embed_model, "input": text},
                timeout=30,
            )
            if response.status_code == 404:
                response = requests.post(
                    f"{self.base_url}/api/embeddings",
                    json={"model": settings.ollama_embed_model, "prompt": text},
                    timeout=30,
                )
                response.raise_for_status()
                return response.json()["embedding"]
            response.raise_for_status()
            return response.json()["embeddings"][0]
        except Exception as e:
            raise RuntimeError(f"Embedding failed: {e}")
        
    def health_check(self) -> dict:
        """Return connection + model availability status."""
        try:
            response = requests.get(f"{self.base_url}/api/tags", timeout=5)
            response.raise_for_status()
            models = [m["name"] for m in response.json().get("models", [])]
            main_ok       = any(self.model.split(":")[0] in m for m in models)
            embed_ok      = any(settings.ollama_embed_model.split(":")[0] in m for m in models)
            classifier_ok = any(settings.ollama_classifier_model.split(":")[0] in m for m in models)
            all_ok = main_ok and embed_ok and classifier_ok
            missing = []
            if not main_ok:       missing.append(settings.ollama_model)
            if not embed_ok:      missing.append(settings.ollama_embed_model)
            if not classifier_ok: missing.append(settings.ollama_classifier_model)
            return {
                "connected": True,
                "main_model": self.model,
                "main_model_available": main_ok,
                "classifier_model": settings.ollama_classifier_model,
                "classifier_model_available": classifier_ok,
                "embed_model_available": embed_ok,
                "available_models": models,
                "message": "OK" if all_ok else
                           f"Missing models. Run: " +
                           " && ".join(f"ollama pull {m}" for m in missing),
            }
        except Exception as e:
            return {
                "connected": False,
                "main_model_available": False,
                "classifier_model_available": False,
                "embed_model_available": False,
                "available_models": [],
                "message": f"Ollama not reachable at {self.base_url}: {e}",
            }


# Singleton — main model (Llama 3.1 8B) for DSL generation and narrative
ollama = OllamaClient()


class ClassifierOllamaClient(OllamaClient):
    """
    Dedicated client for intent classification using Qwen2.5 7B.

    Controlled by USE_CLASSIFIER_MODEL in .env:
      true  (default) → uses OLLAMA_CLASSIFIER_MODEL (qwen2.5:7b)
      false           → uses OLLAMA_MODEL (llama3.1:8b) — single-model mode

    Falls back to main model automatically if classifier model not found.
    """

    def __init__(self):
        super().__init__()
        if settings.use_classifier_model:
            self.model = settings.ollama_classifier_model
        # If use_classifier_model=false, self.model stays as settings.ollama_model
        self.timeout = 60

    def chat(self, messages, temperature=0.0, max_tokens=200,
             json_mode=False, system=None):
        result = super().chat(
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
            json_mode=json_mode,
            system=system,
        )
        # Auto-fallback if classifier model not pulled
        if result.startswith("ERROR:") and "not found" in result.lower():
            import sys
            print(
                f"[WARNING] Classifier model '{self.model}' not found. "
                f"Falling back to '{settings.ollama_model}'. "
                f"Run: ollama pull {self.model}",
                file=sys.stderr,
            )
            self.model = settings.ollama_model
            return super().chat(
                messages=messages,
                temperature=temperature,
                max_tokens=max_tokens,
                json_mode=json_mode,
                system=system,
            )
        return result


# Singleton — classifier model (Qwen2.5 7B) for intent classification
classifier_ollama = ClassifierOllamaClient()