#!/usr/bin/env python3
"""
SentinelOne Singularity Data Lake (SDL) API Client

Wraps all 10 SDL methods with automatic key selection, retry logic, and pagination.
"""

import json
import os
import random
import time
import uuid
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Union
from urllib.parse import urljoin

import requests

CONFIG_PATH = Path(__file__).parent.parent / "config.json"


class SDLError(Exception):
    """Base exception for SDL API errors."""
    def __init__(self, message: str, status: Optional[str] = None, response: Optional[Dict] = None):
        super().__init__(message)
        self.status = status
        self.response = response


class SDLAuthError(SDLError):
    """Authentication or permission error."""
    pass


class SDLRateLimitError(SDLError):
    """Rate limit exceeded."""
    def __init__(self, message: str, retry_after: float = 1.0, **kwargs):
        super().__init__(message, **kwargs)
        self.retry_after = retry_after


class SDLClient:
    """
    Client for the SentinelOne Singularity Data Lake API.
    
    Automatically selects the appropriate key per method and handles retries.
    """
    
    DEFAULT_TIMEOUT = 120
    MAX_RETRIES = 5
    
    def __init__(self, config_path: Optional[Path] = None):
        self._config = self._load_config(config_path or CONFIG_PATH)
        self._session = requests.Session()
        self._session.headers["Content-Type"] = "application/json"
    
    def _load_config(self, path: Path) -> Dict[str, str]:
        """Load config from file, with env var overrides."""
        config = {}
        if path.exists():
            with open(path) as f:
                config = json.load(f)
        
        # Env vars override file
        env_map = {
            "SDL_BASE_URL": "base_url",
            "SDL_LOG_WRITE_KEY": "log_write_key",
            "SDL_LOG_READ_KEY": "log_read_key",
            "SDL_CONFIG_READ_KEY": "config_read_key",
            "SDL_CONFIG_WRITE_KEY": "config_write_key",
            "SDL_CONSOLE_API_TOKEN": "console_api_token",
            "SDL_S1_SCOPE": "s1_scope",
            "SDL_VERIFY_TLS": "verify_tls",
        }
        for env_key, config_key in env_map.items():
            if os.environ.get(env_key):
                config[config_key] = os.environ[env_key]
        
        return config
    
    @property
    def base_url(self) -> str:
        url = self._config.get("base_url", "")
        if not url:
            raise SDLError("base_url not configured")
        return url.rstrip("/")
    
    @property
    def verify_tls(self) -> bool:
        val = self._config.get("verify_tls", "true")
        return str(val).lower() not in ("false", "0", "no")
    
    def _get_key(self, key_type: str) -> str:
        """
        Get the appropriate key for the operation type.
        
        Key chains (first non-empty wins):
        - log_write: log_write_key → console_api_token
        - log_write_strict: log_write_key only (uploadLogs rejects console tokens)
        - log_read: log_read_key → config_read_key → config_write_key → console_api_token
        - config_read: config_read_key → config_write_key → console_api_token
        - config_write: config_write_key → console_api_token
        """
        chains = {
            "log_write": ["log_write_key", "console_api_token"],
            "log_write_strict": ["log_write_key"],
            "log_read": ["log_read_key", "config_read_key", "config_write_key", "console_api_token"],
            "config_read": ["config_read_key", "config_write_key", "console_api_token"],
            "config_write": ["config_write_key", "console_api_token"],
        }
        
        chain = chains.get(key_type, [])
        for key_name in chain:
            key = self._config.get(key_name, "")
            if key:
                return key
        
        raise SDLAuthError(f"No valid key found for {key_type}. Configure one of: {chain}")
    
    def _build_headers(self, key_type: str) -> Dict[str, str]:
        """Build request headers with auth."""
        key = self._get_key(key_type)
        headers = {"Authorization": f"Bearer {key}"}
        
        # Add S1-Scope if using console token with multi-site/account access
        if key == self._config.get("console_api_token") and self._config.get("s1_scope"):
            headers["S1-Scope"] = self._config["s1_scope"]
        
        return headers
    
    def _request(
        self,
        method: str,
        endpoint: str,
        key_type: str,
        params: Optional[Dict] = None,
        json_body: Optional[Dict] = None,
        data: Optional[str] = None,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> Dict[str, Any]:
        """
        Make an API request with automatic retries.
        
        Handles:
        - HTTP 429 with Retry-After
        - HTTP 5xx
        - SDL status: error/server/backoff (can come in a 200)
        """
        url = f"{self.base_url}/api/{endpoint.lstrip('/')}"
        headers = self._build_headers(key_type)
        
        if data is not None:
            headers["Content-Type"] = "text/plain"
        
        last_error = None
        for attempt in range(self.MAX_RETRIES):
            try:
                resp = self._session.request(
                    method,
                    url,
                    params=params,
                    json=json_body,
                    data=data,
                    headers=headers,
                    timeout=timeout,
                    verify=self.verify_tls,
                )
            except requests.exceptions.ReadTimeout as e:
                last_error = e
                if attempt < self.MAX_RETRIES - 1:
                    wait = self._backoff_delay(attempt)
                    print(f"  [timeout] attempt {attempt+1}/{self.MAX_RETRIES}, retrying in {wait:.1f}s...")
                    time.sleep(wait)
                    continue
                raise SDLError(f"Read timeout after {self.MAX_RETRIES} attempts: {e}")
            except requests.exceptions.ConnectionError as e:
                last_error = e
                if attempt < self.MAX_RETRIES - 1:
                    wait = self._backoff_delay(attempt)
                    print(f"  [conn error] attempt {attempt+1}/{self.MAX_RETRIES}, retrying in {wait:.1f}s...")
                    time.sleep(wait)
                    continue
                raise SDLError(f"Connection error after {self.MAX_RETRIES} attempts: {e}")
                
            # Handle HTTP-level errors
            if resp.status_code == 401:
                raise SDLAuthError(
                    f"Authentication failed: {resp.text}",
                    status="error/client/noPermission",
                )
            
            if resp.status_code == 429:
                retry_after = float(resp.headers.get("Retry-After", 1))
                if attempt < self.MAX_RETRIES - 1:
                    time.sleep(retry_after)
                    continue
                raise SDLRateLimitError(
                    f"Rate limit exceeded",
                    retry_after=retry_after,
                )
            
            if resp.status_code >= 500:
                if attempt < self.MAX_RETRIES - 1:
                    time.sleep(self._backoff_delay(attempt))
                    continue
                resp.raise_for_status()
            
            resp.raise_for_status()
            
            # Parse response
            result = resp.json()
            
            # Handle SDL-level backoff (can come in a 200)
            status = result.get("status", "")
            if status == "error/server/backoff":
                wait = result.get("cpuUsageSecondsToWait", 1)
                if attempt < self.MAX_RETRIES - 1:
                    time.sleep(wait)
                    continue
                raise SDLRateLimitError(
                    f"Server backoff requested",
                    retry_after=wait,
                    response=result,
                )
            
            if status.startswith("error/"):
                raise SDLError(
                    result.get("message", status),
                    status=status,
                    response=result,
                )
            
            return result
        
        raise SDLError(f"Max retries exceeded: {last_error}")
    
    def _backoff_delay(self, attempt: int) -> float:
        """Exponential backoff with jitter."""
        base = min(2 ** attempt, 30)
        return base + random.uniform(0, 1)
    
    # =========================================================================
    # Log Read Methods
    # =========================================================================
    
    def query(
        self,
        filter: str = "",
        start_time: str = "24h",
        end_time: Optional[str] = None,
        max_count: int = 100,
        page_mode: str = "head",
        columns: Optional[List[str]] = None,
        priority: str = "low",
        continuation_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Search for log events matching a filter.
        
        Args:
            filter: SDL filter expression (e.g., "status >= 400")
            start_time: Start of time range (e.g., "1h", "24h", "7d", or epoch nanos)
            end_time: End of time range (default: now)
            max_count: Max events to return (1-5000)
            page_mode: "head" (oldest first) or "tail" (newest first)
            columns: Fields to return (default: all)
            priority: "low" or "high" (affects rate limit bucket)
            continuation_token: For pagination
        
        Returns:
            {"status": "success", "matches": [...], "continuationToken": "..."}
        """
        body: Dict[str, Any] = {
            "queryType": "log",
            "filter": filter,
            "startTime": start_time,
            "maxCount": max_count,
            "pageMode": page_mode,
            "priority": priority,
        }
        if end_time:
            body["endTime"] = end_time
        if columns:
            body["columns"] = columns
        if continuation_token:
            body["continuationToken"] = continuation_token
        
        return self._request("POST", "query", "log_read", json_body=body)
    
    def iter_query(
        self,
        filter: str = "",
        start_time: str = "24h",
        end_time: Optional[str] = None,
        max_total: int = 1000,
        columns: Optional[List[str]] = None,
        priority: str = "low",
    ) -> Iterator[Dict[str, Any]]:
        """
        Iterate through all matching events with automatic pagination.
        
        Args:
            filter: SDL filter expression
            start_time: Start of time range
            end_time: End of time range
            max_total: Maximum total events to return
            columns: Fields to return
            priority: "low" or "high"
        
        Yields:
            Individual event dicts
        """
        continuation_token = None
        total = 0
        page_size = min(1000, max_total)
        
        while total < max_total:
            result = self.query(
                filter=filter,
                start_time=start_time,
                end_time=end_time,
                max_count=min(page_size, max_total - total),
                columns=columns,
                priority=priority,
                continuation_token=continuation_token,
            )
            
            matches = result.get("matches", [])
            for event in matches:
                yield event
                total += 1
                if total >= max_total:
                    return
            
            continuation_token = result.get("continuationToken")
            if not continuation_token or not matches:
                break
    
    def power_query(
        self,
        query: str,
        start_time: str = "24h",
        end_time: Optional[str] = None,
        priority: str = "low",
    ) -> Dict[str, Any]:
        """
        Execute a PowerQuery.
        
        Args:
            query: PowerQuery string (e.g., "dataset='accesslog' | group count() by status")
            start_time: Start of time range
            end_time: End of time range
            priority: "low" or "high"
        
        Returns:
            {"status": "success", "matchingEvents": N, "columns": [...], "values": [[...], ...]}
        """
        body: Dict[str, Any] = {
            "query": query,
            "startTime": start_time,
            "priority": priority,
        }
        if end_time:
            body["endTime"] = end_time
        
        return self._request("POST", "powerQuery", "log_read", json_body=body)
    
    def facet_query(
        self,
        field: str,
        filter: str = "",
        start_time: str = "24h",
        end_time: Optional[str] = None,
        max_count: int = 100,
        priority: str = "low",
    ) -> Dict[str, Any]:
        """
        Get top values for a field.
        
        Args:
            field: Field to facet on (e.g., "srcIp", "status")
            filter: SDL filter expression
            start_time: Start of time range
            end_time: End of time range
            max_count: Max values to return (1-1000)
            priority: "low" or "high"
        
        Returns:
            {"status": "success", "matchingEvents": N, "values": [{"value": "...", "count": N}, ...]}
        """
        body: Dict[str, Any] = {
            "queryType": "facet",
            "field": field,
            "filter": filter,
            "startTime": start_time,
            "maxCount": max_count,
            "priority": priority,
        }
        if end_time:
            body["endTime"] = end_time
        
        return self._request("POST", "facetQuery", "log_read", json_body=body)
    
    def timeseries_query(
        self,
        queries: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Execute one or more timeseries queries.
        
        Args:
            queries: List of query objects, each with:
                - filter: SDL filter expression
                - function: "count", "mean", "min", "max", "sum", "p50", "p90", "p99", etc.
                - startTime: Start of time range
                - endTime: End of time range (optional)
                - buckets: Number of time buckets (default: 1)
                - priority: "low" or "high" (optional)
        
        Returns:
            {"status": "success", "results": [{"values": [N, ...], ...}, ...]}
        """
        return self._request("POST", "timeseriesQuery", "log_read", json_body={"queries": queries})
    
    def numeric_query(
        self,
        queries: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Execute one or more numeric aggregate queries.
        
        Args:
            queries: List of query objects, each with:
                - filter: SDL filter expression
                - function: "count", "mean", "min", "max", "sum", "p50", "p90", "p99", etc.
                - startTime: Start of time range
                - endTime: End of time range (optional)
                - priority: "low" or "high" (optional)
        
        Returns:
            {"status": "success", "results": [{"value": N, ...}, ...]}
        """
        return self._request("POST", "numericQuery", "log_read", json_body={"queries": queries})
    
    # =========================================================================
    # Log Write Methods
    # =========================================================================
    
    @staticmethod
    def new_session_id() -> str:
        """Generate a new session ID for addEvents."""
        return str(uuid.uuid4())
    
    @staticmethod
    def now_ns() -> int:
        """Current time in nanoseconds since epoch."""
        return int(time.time() * 1_000_000_000)
    
    def upload_logs(
        self,
        log_data: str,
        parser: str,
        server_host: Optional[str] = None,
        log_file: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Upload plain-text log data.
        
        IMPORTANT: Requires a Log Write Access key. Console tokens are rejected.
        
        Args:
            log_data: Raw log text (newline-separated lines)
            parser: Parser name to apply
            server_host: Source host identifier
            log_file: Source file path (optional)
        
        Returns:
            {"status": "success", "bytesCharged": N}
        
        Limits:
            - 6 MB max per request
            - 10 GB/day total
        """
        params: Dict[str, str] = {"parser": parser}
        if server_host:
            params["host"] = server_host
        if log_file:
            params["logfile"] = log_file
        
        return self._request(
            "POST",
            "uploadLogs",
            "log_write_strict",
            params=params,
            data=log_data,
        )
    
    def add_events(
        self,
        session: str,
        events: List[Dict[str, Any]],
        session_info: Optional[Dict[str, Any]] = None,
        threads: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Ingest structured events.
        
        Args:
            session: Session ID (use new_session_id() to generate)
            events: List of event objects, each with:
                - ts: Timestamp in nanoseconds
                - sev: Severity (0-6, optional)
                - attrs: Dict of event attributes
                - thread: Thread ID (optional, for multi-thread sessions)
            session_info: Session-level attributes (sent once per session)
            threads: Thread definitions for multi-thread sessions
        
        Returns:
            {"status": "success", "bytesCharged": N}
        
        Session rules:
            - Keep ≤ 2.5 MB/s per session
            - Only one in-flight request per session
            - For parallel ingest, use multiple sessions
        """
        body: Dict[str, Any] = {
            "session": session,
            "events": events,
        }
        if session_info:
            body["sessionInfo"] = session_info
        if threads:
            body["threads"] = threads
        
        return self._request("POST", "addEvents", "log_write", json_body=body)
    
    # =========================================================================
    # Configuration File Methods
    # =========================================================================
    
    def list_files(self, path_prefix: str = "") -> Dict[str, Any]:
        """
        List configuration files.
        
        Args:
            path_prefix: Filter by path prefix (e.g., "/logParsers/")
        
        Returns:
            {"status": "success", "paths": ["/path1", "/path2", ...]}
        """
        params = {}
        if path_prefix:
            params["pathPrefix"] = path_prefix
        
        return self._request("POST", "listFiles", "config_read", json_body=params if params else {})
    
    def get_file(self, path: str) -> Dict[str, Any]:
        """
        Get a configuration file.
        
        Args:
            path: File path (e.g., "/logParsers/MyParser")
        
        Returns:
            {"status": "success", "path": "...", "content": "...", "version": N, "createDate": "...", "modDate": "..."}
        """
        return self._request("POST", "getFile", "config_read", json_body={"path": path})
    
    def put_file(
        self,
        path: str,
        content: Optional[str] = None,
        delete: bool = False,
        expected_version: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Create, update, or delete a configuration file.
        
        IMPORTANT: This is destructive. Always get_file first to check current content/version.
        
        Args:
            path: File path (e.g., "/logParsers/MyParser")
            content: New file content (required unless delete=True)
            delete: If True, delete the file
            expected_version: Fail if current version doesn't match (optimistic locking)
        
        Returns:
            {"status": "success", "path": "...", "version": N}
        """
        body: Dict[str, Any] = {"path": path}
        
        if delete:
            body["deleteFile"] = True
        elif content is not None:
            body["content"] = content
        else:
            raise SDLError("Either content or delete=True is required")
        
        if expected_version is not None:
            body["expectedVersion"] = expected_version
        
        return self._request("POST", "putFile", "config_write", json_body=body)


if __name__ == "__main__":
    # Quick connectivity test
    c = SDLClient()
    print(f"Base URL: {c.base_url}")
    print("Client initialized successfully.")
