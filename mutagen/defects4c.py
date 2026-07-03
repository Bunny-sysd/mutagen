"""
Defects4C Benchmark API Client.

Interfaces with the Defects4C Bug Helper REST API to automate C/C++ program
repair benchmarking.
"""

from __future__ import annotations
import time
import requests


class Defects4CError(Exception):
    """Exception raised for Defects4C API integration errors."""
    pass


class Defects4CClient:
    """Client to interact with the Defects4C REST API service."""

    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")

    def list_projects(self) -> list[str]:
        """Query GET /projects to retrieve all available benchmark projects."""
        url = f"{self.base_url}/projects"
        try:
            resp = requests.get(url, timeout=10)
            if resp.status_code == 200:
                return resp.json().get("projects", [])
            raise Defects4CError(f"Failed to list projects: HTTP {resp.status_code}")
        except Exception as e:
            raise Defects4CError(f"HTTP request to /projects failed: {e}") from e

    def reproduce(self, bug_id: str, is_force_cleanup: bool = True) -> bool:
        """
        Initiate bug reproduction via POST /reproduce and poll GET /status/{handle}
        until the setup completes successfully.
        """
        url = f"{self.base_url}/reproduce"
        payload = {
            "bug_id": bug_id,
            "is_force_cleanup": is_force_cleanup
        }
        try:
            resp = requests.post(url, json=payload, timeout=15)
            if resp.status_code != 200:
                raise Defects4CError(f"Failed to start reproduction: HTTP {resp.status_code} - {resp.text}")
            
            handle = resp.json().get("handle")
            if not handle:
                raise Defects4CError("Reproduction response did not return a status handle.")
            
            # Poll status
            status_url = f"{self.base_url}/status/{handle}"
            polls = 0
            while polls < 120:  # Up to 10 minutes (5s interval)
                time.sleep(5)
                polls += 1
                status_resp = requests.get(status_url, timeout=10)
                if status_resp.status_code != 200:
                    raise Defects4CError(f"Failed to query task status: HTTP {status_resp.status_code}")
                
                data = status_resp.json()
                status = data.get("status", "").lower()
                
                if status == "success" or status == "completed":
                    return True
                elif status == "failed" or status == "error":
                    error_msg = data.get("message", "Unknown reproduction failure")
                    raise Defects4CError(f"Reproduction task failed: {error_msg}")
                    
            raise Defects4CError("Reproduction timed out after 10 minutes.")
        except Exception as e:
            if not isinstance(e, Defects4CError):
                raise Defects4CError(f"HTTP request to /reproduce failed: {e}") from e
            raise

    def fix(self, bug_id: str, patch_path: str) -> dict:
        """
        Apply a patch file via POST /fix and verify if the test cases pass.
        Returns a dictionary containing the verification outcome and error messages.
        """
        url = f"{self.base_url}/fix"
        payload = {
            "bug_id": bug_id,
            "patch_path": patch_path
        }
        try:
            resp = requests.post(url, json=payload, timeout=60)
            if resp.status_code == 200:
                return resp.json()
            raise Defects4CError(f"Fix endpoint failed: HTTP {resp.status_code} - {resp.text}")
        except Exception as e:
            raise Defects4CError(f"HTTP request to /fix failed: {e}") from e

    def error_dig(self, handle: str) -> dict:
        """
        Query POST /error_dig to diagnose compilation/test failures.
        """
        url = f"{self.base_url}/error_dig"
        payload = {"handle": handle}
        try:
            resp = requests.post(url, json=payload, timeout=15)
            if resp.status_code == 200:
                return resp.json()
            raise Defects4CError(f"Error diagnostics failed: HTTP {resp.status_code}")
        except Exception as e:
            raise Defects4CError(f"HTTP request to /error_dig failed: {e}") from e
