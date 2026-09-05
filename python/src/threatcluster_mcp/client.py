"""HTTP client for the ThreatCluster public API.

Security contract
-----------------
* The API key is resolved once (env var first, then the tc-cli credential
  store), kept on the client instance, and leaves the process in exactly one
  place: the ``X-API-Key`` header (or ``Authorization: Bearer`` for a JWT
  minted by ``tc login``) of requests to the configured API base.
* It is never logged, never written to disk, never echoed in an error. Every
  string that can reach the MCP transport goes through :func:`redact`.
* No telemetry: the only network destination is ``THREATCLUSTER_API_BASE``.
* stdout is the MCP transport; this module never writes to it.
"""
from __future__ import annotations

import json
import logging
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import httpx

from . import __version__

log = logging.getLogger("threatcluster_mcp")

DEFAULT_API_BASE = "https://threatcluster.io/api/public/v1"
DEFAULT_SITE = "https://threatcluster.io"
FREE_KEY_URL = "https://threatcluster.io/api"
PRICING_URL = "https://threatcluster.io/pricing"
ENV_API_KEY = "THREATCLUSTER_API_KEY"
ENV_API_BASE = "THREATCLUSTER_API_BASE"
ENV_SITE = "THREATCLUSTER_SITE"
ENV_TC_CLI_TOKEN = "TC_REFRESH_TOKEN"  # honoured by tc-cli; same credential
USER_AGENT = f"threatcluster-mcp/{__version__} (python)"
REQUEST_TIMEOUT = 45.0


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _epoch_iso(epoch: Optional[int]) -> Optional[str]:
    if epoch is None:
        return None
    return datetime.fromtimestamp(int(epoch), tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# Credential resolution
# ---------------------------------------------------------------------------
def _tc_cli_credential_file() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "tc-cli" / "credentials"


def _read_tc_cli_file() -> Optional[str]:
    """The 0600 file tc-cli falls back to when no keyring is available. Same
    policy as tc_cli.credentials: refuse a file that is group/world readable
    or owned by someone else."""
    path = _tc_cli_credential_file()
    try:
        if not path.exists():
            return None
        st = path.stat()
        if (st.st_mode & 0o777) != 0o600:
            log.warning("%s is not mode 0600; ignoring it", path)
            return None
        if hasattr(os, "geteuid") and st.st_uid != os.geteuid():
            log.warning("%s is not owned by the current user; ignoring it", path)
            return None
        return path.read_text().strip() or None
    except OSError:
        return None


def resolve_api_key() -> tuple[Optional[str], str]:
    """Return ``(key, source)``. Order: THREATCLUSTER_API_KEY, TC_REFRESH_TOKEN,
    the tc-cli store via ``tc_cli.credentials`` (keyring or 0600 file) when
    tc-cli is installed, else the 0600 file directly. ``source`` is one of
    ``env``, ``tc-cli-env``, ``tc-cli``, ``tc-cli-file``, ``none``."""
    v = (os.environ.get(ENV_API_KEY) or "").strip()
    if v:
        return v, "env"
    v = (os.environ.get(ENV_TC_CLI_TOKEN) or "").strip()
    if v:
        return v, "tc-cli-env"
    try:
        from tc_cli import credentials as _tc_credentials  # type: ignore
    except Exception:
        _tc_credentials = None
    if _tc_credentials is not None:
        try:
            v = _tc_credentials.load()
            if v:
                return v.strip(), "tc-cli"
        except Exception as e:  # CredentialError on a bad file mode, etc.
            log.warning("tc-cli credential store unavailable: %s", type(e).__name__)
    v = _read_tc_cli_file()
    if v:
        return v, "tc-cli-file"
    return None, "none"


def resolve_api_base() -> str:
    return (os.environ.get(ENV_API_BASE) or DEFAULT_API_BASE).strip().rstrip("/")


def resolve_site() -> str:
    return (os.environ.get(ENV_SITE) or DEFAULT_SITE).strip().rstrip("/")


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------
class ApiError(Exception):
    """An API response we cannot turn into a tool result. ``to_text()`` is the
    message an agent sees; it is already redacted."""

    def __init__(self, status: int, code: str, message: str, *, retry_after: Optional[int] = None,
                 hint: Optional[str] = None, path: str = "", cost: int = 0) -> None:
        super().__init__(message)
        self.status = status
        self.cost = cost
        self.code = code
        self.message = message
        self.retry_after = retry_after
        self.hint = hint
        self.path = path

    def to_text(self) -> str:
        head = f"ThreatCluster API {self.status} {self.code}" if self.status else f"ThreatCluster API {self.code}"
        parts = [f"{head}: {self.message}"]
        if self.retry_after is not None:
            parts.append(f"Retry after {self.retry_after} seconds.")
        if self.hint:
            parts.append(self.hint)
        if self.cost:
            parts.append(f"(cost: {self.cost} credits)")
        return " ".join(parts)

    def to_dict(self) -> dict:
        d: dict[str, Any] = {"status": self.status, "code": self.code, "message": self.message, "cost": self.cost}
        if self.retry_after is not None:
            d["retry_after"] = self.retry_after
        if self.hint:
            d["hint"] = self.hint
        return d


# ---------------------------------------------------------------------------
# Budget bookkeeping (from response headers; no API call needed to read it)
# ---------------------------------------------------------------------------
class Budget:
    def __init__(self) -> None:
        self.limit: Optional[int] = None
        self.remaining: Optional[int] = None
        self.reset_epoch: Optional[int] = None
        self.credits_balance: Optional[int] = None
        self.session_calls = 0
        self.session_cost = 0
        self.started_at = now_iso()
        self.last_response_at: Optional[str] = None
        self.last_status: Optional[int] = None
        self.last_error: Optional[dict] = None
        self._call_times: list[float] = []

    @staticmethod
    def _int(v: Optional[str]) -> Optional[int]:
        if v is None:
            return None
        try:
            return int(str(v).strip())
        except ValueError:
            return None

    def observe(self, status: int, headers: Any, cost: int) -> None:
        self.session_calls += 1
        self.session_cost += cost
        t = time.time()
        self._call_times = [x for x in self._call_times if t - x < 60.0] + [t]
        self.last_response_at = now_iso()
        self.last_status = status
        lim = self._int(headers.get("X-RateLimit-Limit"))
        rem = self._int(headers.get("X-RateLimit-Remaining"))
        rst = self._int(headers.get("X-RateLimit-Reset"))
        bal = self._int(headers.get("X-Credits-Balance"))
        if lim is not None:
            self.limit = lim
        if rem is not None:
            self.remaining = rem
        if rst is not None:
            self.reset_epoch = rst
        if bal is not None:
            self.credits_balance = bal

    def requests_last_minute(self) -> int:
        t = time.time()
        return sum(1 for x in self._call_times if t - x < 60.0)

    def brief(self) -> Optional[dict]:
        """The small block attached to every tool result."""
        if self.limit is None and self.remaining is None:
            return None
        return {"remaining": self.remaining, "limit": self.limit, "resets_at": _epoch_iso(self.reset_epoch)}

    def snapshot(self) -> dict:
        return {
            "daily_credits": {
                "limit": self.limit,
                "remaining": self.remaining,
                "resets_at": _epoch_iso(self.reset_epoch),
                "pack_balance": self.credits_balance,
            },
            "session": {
                "started_at": self.started_at,
                "api_calls": self.session_calls,
                "credits_spent": self.session_cost,
                "requests_last_minute": self.requests_last_minute(),
            },
            "last_response": {"at": self.last_response_at, "status": self.last_status},
            "last_error": self.last_error,
        }


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------
class ThreatClusterClient:
    def __init__(self, api_key: Optional[str], *, base: Optional[str] = None, site: Optional[str] = None,
                 key_source: str = "none", timeout: float = REQUEST_TIMEOUT,
                 transport: Optional[httpx.AsyncBaseTransport] = None) -> None:
        self._secret = api_key or ""
        self.key_source = key_source
        self.base = (base or resolve_api_base()).rstrip("/")
        self.site = (site or resolve_site()).rstrip("/")
        self.timeout = timeout
        self._transport = transport
        self._http: Optional[httpx.AsyncClient] = None
        self.budget = Budget()

    # -- key handling ----------------------------------------------------
    @property
    def has_key(self) -> bool:
        return bool(self._secret)

    def redact(self, text: Any) -> str:
        s = "" if text is None else str(text)
        if self._secret and len(self._secret) >= 8:
            s = s.replace(self._secret, "[redacted]")
        return s

    def _auth_headers(self) -> dict[str, str]:
        if not self._secret:
            return {}
        # tc_live_* / tc_agent_* are API keys (X-API-Key). Anything else is a
        # short-lived bearer JWT, e.g. one minted by `tc login`.
        if self._secret.startswith("tc_"):
            return {"X-API-Key": self._secret}
        return {"Authorization": "Bearer " + self._secret}

    def _client(self) -> httpx.AsyncClient:
        if self._http is None:
            self._http = httpx.AsyncClient(
                base_url=self.base,
                headers={"User-Agent": USER_AGENT, "Accept": "application/json", **self._auth_headers()},
                timeout=self.timeout,
                transport=self._transport,
                follow_redirects=False,
            )
        return self._http

    async def aclose(self) -> None:
        if self._http is not None:
            await self._http.aclose()
            self._http = None

    # -- requests --------------------------------------------------------
    async def get(self, path: str, params: Optional[dict[str, Any]] = None) -> tuple[Any, int]:
        """GET ``path`` (relative to the API base). Returns ``(json, cost)``.
        Raises :class:`ApiError` for any non-2xx status, network failure or
        non-JSON body. ``None``-valued params are dropped."""
        clean = {k: v for k, v in (params or {}).items() if v is not None and v != ""}
        try:
            resp = await self._client().get(path, params=clean)
        except httpx.TimeoutException:
            err = ApiError(0, "timeout", f"no response from {self.base} within {int(self.timeout)}s", path=path)
            self.budget.last_error = err.to_dict()
            raise err
        except httpx.HTTPError as e:
            err = ApiError(0, "network_error", self.redact(f"{type(e).__name__}: {e}"), path=path,
                           hint=f"Check {ENV_API_BASE} (currently {self.base}).")
            self.budget.last_error = err.to_dict()
            raise err
        cost = Budget._int(resp.headers.get("X-Request-Cost")) or 0
        self.budget.observe(resp.status_code, resp.headers, cost)
        body: Any
        try:
            body = resp.json()
        except (json.JSONDecodeError, ValueError):
            body = None
        if resp.status_code >= 400:
            err = self._error_from(resp.status_code, resp.headers, body, resp.text, path)
            err.cost = cost
            self.budget.last_error = err.to_dict()
            raise err
        if body is None:
            err = ApiError(resp.status_code, "bad_response", "the API returned a non-JSON body", path=path)
            self.budget.last_error = err.to_dict()
            raise err
        self.budget.last_error = None
        return body, cost

    def _error_from(self, status: int, headers: Any, body: Any, text: str, path: str) -> ApiError:
        code = ""
        message = ""
        detail = body.get("detail") if isinstance(body, dict) else None
        if isinstance(detail, dict):
            code = str(detail.get("error") or "")
            message = str(detail.get("message") or "")
        elif isinstance(detail, str):
            message = detail
        if isinstance(body, dict):
            if not code and isinstance(body.get("error"), str):
                code = body["error"]
            if not message and isinstance(body.get("message"), str):
                message = body["message"]
        if not message:
            message = (text or "").strip()[:300] or "no error body"
        retry_after = Budget._int(headers.get("Retry-After"))
        if retry_after is None and isinstance(detail, dict):
            retry_after = Budget._int(detail.get("retry_after"))
        hint: Optional[str] = None
        if status == 401:
            code = code or "unauthorized"
            hint = (f"Set {ENV_API_KEY} to a ThreatCluster API key (tc_live_... or tc_agent_...). "
                    f"Free keys: {FREE_KEY_URL}")
        elif status == 403:
            if code == "insufficient_scope" and isinstance(detail, dict):
                req = detail.get("required_scope")
                granted = detail.get("granted_scopes") or []
                hint = (f"This key lacks the '{req}' scope (granted: {', '.join(granted) or 'none'}). "
                        f"Free keys carry the five read scopes; MSSP scopes need a Business or MSSP plan: {PRICING_URL}")
            elif code == "lookback_exceeded":
                hint = f"Free keys see the last {detail.get('lookback_days', 7) if isinstance(detail, dict) else 7} days; Researcher and above have no lookback limit: {PRICING_URL}"
            else:
                code = code or "forbidden"
        elif status == 404:
            code = "not_found"
            message = f"nothing matches {path}"
        elif status == 429:
            code = code or "rate_limited"
            if retry_after is None:
                retry_after = 60
            if code == "daily_budget_exceeded":
                hint = f"The daily budget refills at 00:00 UTC. Credit packs and paid plans lift it: {PRICING_URL}"
            else:
                hint = "Space calls out; free keys get 30 requests a minute."
        elif status >= 500:
            code = code or "server_error"
            hint = "Temporary; retry once after a few seconds."
        code = code or f"http_{status}"
        # Path is safe (no key in it); message is scrubbed regardless.
        return ApiError(status, self.redact(code), self.redact(message), retry_after=retry_after,
                        hint=hint, path=path)


def redact_all(secret: str, text: str) -> str:
    """Module-level helper for places without a client (e.g. crash output)."""
    if secret and len(secret) >= 8:
        return text.replace(secret, "[redacted]")
    return text


_SECRET_LIKE = re.compile(r"(tc_(?:live|agent)_[A-Za-z0-9_\-]{6,})")


def scrub_key_shapes(text: str) -> str:
    """Belt and braces: mask anything shaped like a ThreatCluster key even if
    it is not the configured one (e.g. a key pasted into a tool argument)."""
    return _SECRET_LIKE.sub("tc_[redacted]", text)
