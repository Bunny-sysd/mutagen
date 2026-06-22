import threading


class SwarmBalancer:
    def __init__(self, urls: list[str]):
        self.urls = [url.strip() for url in urls if url.strip()]
        self._lock = threading.Lock()
        self._index = 0

    def get_next_node(self) -> str:
        if not self.urls:
            return ""
        with self._lock:
            url = self.urls[self._index]
            self._index = (self._index + 1) % len(self.urls)
            return url
