from mutagen.engines.gemini import GeminiEngine
from mutagen.engines.openai_engine import OpenAIEngine
from mutagen.engines.ollama import OllamaEngine

def get_engine(provider: str, api_key: str, model: str = "", debug: bool = False, console = None):
    provider = provider.lower()
    if provider == "gemini":
        return GeminiEngine(api_key=api_key)
    elif provider == "openai":
        return OpenAIEngine(api_key=api_key, model=model)
    elif provider == "ollama":
        return OllamaEngine(model=model)
    else:
        raise ValueError(f"Unknown provider: {provider}")
