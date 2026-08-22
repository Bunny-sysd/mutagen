import threading
import time
from abc import ABC, abstractmethod

from rich.console import Console

_hb_console = Console(force_terminal=True, force_jupyter=False)


class BaseEngine(ABC):
    @property
    def lang(self) -> str:
        return getattr(self, "language", "c").lower()

    @property
    def lang_name(self) -> str:
        if self.lang == "rust":
            return "Rust"
        elif self.lang == "go":
            return "Go"
        elif self.lang == "java":
            return "Java"
        elif self.lang == "csharp":
            return "C#"
        elif self.lang == "solidity":
            return "Solidity"
        elif self.lang == "html":
            return "HTML"
        elif self.lang == "javascript":
            return "JavaScript"
        elif self.lang == "css":
            return "CSS"
        elif self.lang == "python":
            return "Python"
        return "C"

    @property
    def lang_ext(self) -> str:
        if self.lang == "rust":
            return "rs"
        elif self.lang == "go":
            return "go"
        elif self.lang == "java":
            return "java"
        elif self.lang == "csharp":
            return "cs"
        elif self.lang == "solidity":
            return "sol"
        elif self.lang == "html":
            return "html"
        elif self.lang == "javascript":
            return "js"
        elif self.lang == "css":
            return "css"
        elif self.lang == "python":
            return "py"
        return "c"


    @abstractmethod
    def analyze_code(self, source_code: str, max_payloads: int, delivery_mode: str, debug: bool, profile: str = "legacy-audit") -> list[dict]:
        pass

    @abstractmethod
    def refine_payload(self, source_code: str, failed_args: list[str], failed_input: str, stdout: str, stderr: str, return_code: int, delivery_mode: str, coverage_info: dict | None = None) -> list[dict]:
        pass

    @abstractmethod
    def generate_patch(self, source_code: str, crash_data: dict, debug: bool = False) -> str:
        pass

    @abstractmethod
    def refine_patch(self, source_code: str, bad_patch: str, error_message: str, crash_data: dict, debug: bool = False) -> str:
        pass

    @abstractmethod
    def generate_exploit(self, source_code: str, crash_data: dict, exe_path: str, delivery_mode: str, debug: bool = False) -> str:
        pass

    def deobfuscate_code(self, raw_code: str, debug: bool = False) -> str:
        """AI Symbol Recovery and deobfuscation pass. Retypes/renames symbols and adds inline comments.
        Default implementation returns raw code if not implemented by subclass."""
        return raw_code

    def generate_payloads(self, source_code: str, prompt: str, max_payloads: int, debug: bool = False) -> list[dict]:
        """Generate ordered sequence payloads for session mode fuzzing.
        Default implementation returns empty list."""
        return []


class AiActivityHeartbeat:
    """
    Spawns a lightweight daemon thread during long-running LLM generation calls.
    Every few seconds, it prints an updated status message to the console
    assuring the user that the AI agent is actively thinking and working on the task.
    """
    def __init__(self, task_name: str = "Synthesizing code"):
        self.task_name = task_name
        self._stop_event = threading.Event()
        self._thread = None
        self._start_time = None

    def __enter__(self):
        self._start_time = time.time()
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run_heartbeat, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=1.0)

    def _run_heartbeat(self):
        messages = [
            (10, "⏳ Analyzing code context and planning modifications"),
            (25, "⏳ Large file processing — AI agent is still synthesizing code"),
            (45, "⏳ Complex generation — verifying logic and safety boundaries"),
            (70, "⏳ Taking a little longer than usual — agent is still thinking on complex problem"),
            (100, "⏳ Deep synthesis in progress — resolving AST references and patch structure"),
            (140, "⏳ Still actively processing — streaming full patch implementation"),
        ]
        next_idx = 0
        while not self._stop_event.wait(timeout=1.0):
            elapsed = int(time.time() - self._start_time)
            if next_idx < len(messages) and elapsed >= messages[next_idx][0]:
                text = messages[next_idx][1]
                _hb_console.print(f"[dim]  {text} (elapsed: {elapsed}s)...[/dim]")
                next_idx += 1
            elif next_idx >= len(messages) and elapsed % 30 == 0 and elapsed > 140:
                _hb_console.print(f"[dim]  ⏳ AI agent still actively working on {self.task_name} (elapsed: {elapsed}s)...[/dim]")




