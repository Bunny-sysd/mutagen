from abc import ABC, abstractmethod


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
        return "c"

    @abstractmethod
    def analyze_code(self, source_code: str, max_payloads: int, delivery_mode: str, debug: bool, profile: str = "legacy-audit") -> list[dict]:
        pass

    @abstractmethod
    def refine_payload(self, source_code: str, failed_args: list[str], failed_input: str, stdout: str, stderr: str, return_code: int, delivery_mode: str) -> list[dict]:
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


