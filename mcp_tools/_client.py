"""HTTP client for communicating with the Kali Linux Tools API Server."""

import logging
import threading
from typing import Dict, Any, Optional

import requests

logger = logging.getLogger(__name__)


class KaliToolsClient:
    """Client for communicating with the Kali Linux Tools API Server."""

    MAX_HEAVY_TASKS: int = 5

    def __init__(self, server_url: str, timeout: int = 300):
        self.server_url = server_url.rstrip("/")
        self.timeout = timeout
        self._connect_timeout = 10
        self._heavy_semaphore = threading.Semaphore(self.MAX_HEAVY_TASKS)
        logger.info(f"Initialized Kali Tools Client connecting to {server_url}")

    def safe_get(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        if params is None:
            params = {}
        url = f"{self.server_url}/{endpoint}"
        try:
            logger.debug(f"GET {url} with params: {params}")
            response = requests.get(url, params=params, timeout=(self._connect_timeout, self.timeout))
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed: {str(e)}")
            return {"error": f"Request failed: {str(e)}", "success": False}
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            return {"error": f"Unexpected error: {str(e)}", "success": False}

    def safe_post(self, endpoint: str, json_data: Dict[str, Any]) -> Dict[str, Any]:
        url = f"{self.server_url}/{endpoint}"
        try:
            logger.debug(f"POST {url} with data: {json_data}")
            response = requests.post(url, json=json_data, timeout=(self._connect_timeout, self.timeout))
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed: {str(e)}")
            return {"error": f"Request failed: {str(e)}", "success": False}
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            return {"error": f"Unexpected error: {str(e)}", "success": False}

    def heavy_tool_post(
        self, endpoint: str, json_data: Dict[str, Any], semaphore_timeout: int = 120
    ) -> Dict[str, Any]:
        acquired = self._heavy_semaphore.acquire(timeout=semaphore_timeout)
        if not acquired:
            logger.warning(
                f"Semaphore timeout after {semaphore_timeout}s — too many concurrent heavy tasks"
            )
            return {
                "error": (
                    f"Too many concurrent heavy tasks (max {self.MAX_HEAVY_TASKS}). "
                    f"Timed out after {semaphore_timeout}s waiting for a slot."
                ),
                "success": False,
            }
        try:
            return self.safe_post(endpoint, json_data)
        finally:
            self._heavy_semaphore.release()

    def safe_delete(self, endpoint: str) -> Dict[str, Any]:
        url = f"{self.server_url}/{endpoint}"
        try:
            logger.debug(f"DELETE {url}")
            response = requests.delete(url, timeout=(self._connect_timeout, self.timeout))
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed: {str(e)}")
            return {"error": f"Request failed: {str(e)}", "success": False}
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            return {"error": f"Unexpected error: {str(e)}", "success": False}

    def execute_command(self, command: str) -> Dict[str, Any]:
        return self.safe_post("api/command", {"command": command})

    def check_health(self) -> Dict[str, Any]:
        return self.safe_get("health")
