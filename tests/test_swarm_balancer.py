import os
from unittest.mock import patch

from mutagen.engines.ollama import OllamaEngine
from mutagen.swarm_balancer import SwarmBalancer


def test_round_robin_routing():
    balancer = SwarmBalancer(["http://10.0.0.1:11434", "http://10.0.0.2:11434"])
    assert balancer.get_next_node() == "http://10.0.0.1:11434"
    assert balancer.get_next_node() == "http://10.0.0.2:11434"
    # Wrap around
    assert balancer.get_next_node() == "http://10.0.0.1:11434"


@patch("requests.post")
def test_ollama_swarm_balancing(mock_post):
    mock_post.return_value.status_code = 200
    mock_post.return_value.json.return_value = {"response": "test_reply"}

    with patch.dict(os.environ, {"MUTAGEN_OLLAMA_URL": "http://10.0.0.1:11434,http://10.0.0.2:11434"}):
        engine = OllamaEngine()

        # First call
        engine._generate("test prompt")
        # Second call
        engine._generate("test prompt")

        assert mock_post.call_count == 2
        calls = mock_post.call_args_list
        assert calls[0][0][0] == "http://10.0.0.1:11434/api/generate"
        assert calls[1][0][0] == "http://10.0.0.2:11434/api/generate"

