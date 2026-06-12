from abc import ABC, abstractmethod

class BaseEngine(ABC):
    @abstractmethod
    def analyze_code(self, source_code: str, max_payloads: int, delivery_mode: str, debug: bool) -> list[dict]:
        pass

    @abstractmethod
    def refine_payload(self, source_code: str, failed_args: list[str], failed_input: str, stdout: str, stderr: str, return_code: int, delivery_mode: str) -> list[dict]:
        pass

    @abstractmethod
    def generate_patch(self, source_code: str, crash_data: dict, debug: bool = False) -> str:
        pass

    @abstractmethod
    def generate_exploit(self, source_code: str, crash_data: dict, exe_path: str, delivery_mode: str, debug: bool = False) -> str:
        pass
