from abc import ABC, abstractmethod
import os
from mutagen.state import ProgramContext

class BaseAgent(ABC):
    def __init__(self, name: str, model_provider: str = "gemini", model_name: str = "gemini-2.5-flash", api_key: str = None):
        self.name = name
        self.model_provider = model_provider
        self.model_name = model_name
        self.api_key = api_key or os.environ.get("MUTAGEN_API_KEY") or os.environ.get("GEMINI_API_KEY") or os.environ.get("OPENAI_API_KEY")

    @abstractmethod
    async def process(self, context: ProgramContext) -> ProgramContext:
        """
        Processes the shared ProgramContext state asynchronously, updates it,
        and returns the mutated state context to the orchestrator.
        """
        pass
