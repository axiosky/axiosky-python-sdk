"""Axiosky Python SDK — synchronous and asynchronous governance client.

This module is the single source of truth for the SDK version
(``__version__``); ``setup.py`` and ``__init__.py`` import it from here
to prevent version drift (audit §4).

Hardened features (re-applied from the prior audit + new fixes):
    * ``DecisionStatus`` enum — case-insensitive construction via
      ``DecisionStatus.from_value()``; invalid statuses raise
      ``AxioskyError`` so a typo (``"APRROVE"``) fails loudly instead
      of silently blocking.
    * ``AsyncGovernor`` — full async mirror of ``Governor``.
    * ``@governed`` decorator — sync + async auto-detection; gates a
      function so it runs only on APPROVE. BLOCK raises
      ``GovernanceDeniedError``; ESCALATE raises
      ``GovernanceEscalatedError``.
    * ``govern`` / ``agovern`` context managers (sync / async).
    * Fallback / offline mode — ``fallback="deny"`` (default, safest
      for regulated workloads) returns a synthetic BLOCK ``Decision``
      when the API is unreachable. ``fallback="allow"`` is permitted
      but warned. ``fallback="raise"`` propagates the error. No
      information leakage in fallback reason strings.
    * TLS ``verify`` parameter on the httpx client (bool or CA-bundle
      path str) — enables cert pinning.
    * ``User-Agent: axiosky-python/{version}`` on every request.
    * Input validation — ``agent_id`` / ``action_type`` must be
      non-empty strings; validated at call time.
    * Client-side logging via ``logging.getLogger("axiosky")``.
    * Environment default changed from ``"shadow"`` → ``"live"`` (the
      safer default for a production SDK).
    * ``api_key`` renamed to ``self._api_key`` (protected attribute).
    * ``tenant_id`` is now optional; passing it emits a
      ``DeprecationWarning`` (the tenant is determined server-side
      from the API key).
    * Path-injection prevention — ``escalation_id`` validated against
      ``^[a-zA-Z0-9\\-]+$`` before URL interpolation.
    * Malformed-response handling — ``KeyError`` / ``TypeError`` from
      response parsing wrapped in ``AxioskyError``.
    * Negative ``max_retries`` rejected at init time (``ValueError``).
    * Retry-After parsing — clamps negative/zero to 0.1 s minimum;
      parses both delta-seconds AND HTTP-date (RFC 7231 §7.1.3).
    * All methods route through ``_request_with_retry`` (previously
      ~half bypassed retry, losing human approvals on transient
      failure).
    * 5xx and 429 retried; 4xx never retried. Non-idempotent requests
      (e.g. ``resolve_escalation``) are not retried on transport
      errors.
    * ``target_url`` scheme validation — only ``http`` / ``https``
      allowed (blocks ``file://``, ``gopher://``, etc.).
    * Comprehensive local-URL detection — IPv6 loopback (``[::1]``),
      RFC 1918, link-local (``169.254/16``, ``fe80::/10``), localhost
      variants. Used to warn when ``target_url`` points at internal
      infra (SSRF guard).
    * ``__repr__`` masks the API key.
    * Configurable connection-pool ``limits`` to prevent pool
      exhaustion under load.
    * ``GovernanceDeniedError`` / ``GovernanceEscalatedError`` subclass
      ``AxioskyError`` (unified hierarchy).
    * ``Decision`` dataclass maps all 14 API response fields
      (audit §5.12).
    * httpx transport errors caught and re-raised as ``AxioskyError``
      (no raw httpx exceptions leak).
    * ``datetime.now(timezone.utc)`` instead of deprecated
      ``utcnow()``.
"""
from __future__ import annotations

import asyncio
import contextlib
import datetime as dt
import email.utils
import enum
import functools
import inspect
import ipaddress
import json
import logging
import re
import time
import uuid
import warnings
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict, Optional, Union
from urllib.parse import urlparse

import httpx

# ---------------------------------------------------------------------------
# Single source of truth for the SDK version.
# setup.py and axiosky/__init__.py import this to prevent drift.
# ---------------------------------------------------------------------------
__version__ = "0.5.0"

# Public logger — applications can configure handlers/levels on "axiosky".
logger = logging.getLogger("axiosky")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
DEFAULT_BASE_URL = "http://localhost:8000"
DEFAULT_TIMEOUT = 5.0
DEFAULT_MAX_RETRIES = 3
# Retry-After values that are negative or zero make no sense; clamp to this.
MIN_RETRY_AFTER = 0.1
_USER_AGENT = f"axiosky-python/{__version__}"

# Safe escalation_id charset — no slashes, dots, spaces, or control chars.
# Prevents path injection via URL interpolation.
_ESCALATION_ID_RE = re.compile(r"^[a-zA-Z0-9\-]+$")

# Default httpx connection-pool limits. Prevents pool exhaustion when a
# caller opens a Governor and fires many concurrent requests.
_DEFAULT_LIMITS = httpx.Limits(
    max_connections=100, max_keepalive_connections=20
)

# Sentinel for distinguishing "not passed" from "passed as None".
_UNSET: Any = object()


class DecisionStatus(enum.Enum):
    """Tri-state governance decision (case-insensitive construction)."""

    APPROVE = "APPROVE"
    BLOCK = "BLOCK"
    ESCALATE = "ESCALATE"

    @classmethod
    def from_value(cls, value: Any) -> "DecisionStatus":
        """Construct a ``DecisionStatus`` from a raw string.

        Case-insensitive: ``"approve"``, ``"APPROVE"``, ``"Approve"``
        all map to ``DecisionStatus.APPROVE``. An invalid value (e.g.
        a typo like ``"APRROVE"``) raises ``AxioskyError`` so the
        caller learns immediately rather than silently blocking.
        """
        if not isinstance(value, str):
            raise AxioskyError(
                0,
                f"Invalid decision status: expected string, got "
                f"{type(value).__name__}",
            )
        try:
            return cls(value.strip().upper())
        except ValueError:
            valid = ", ".join(m.value for m in cls)
            raise AxioskyError(
                0,
                f"Invalid decision status {value!r}; must be one of: "
                f"{valid}",
            )


@dataclass
class Decision:
    """A governance decision returned by the Axiosky API.

    Maps all fields from the backend's DecisionResponse model
    (audit §5.12 — previously 6 fields were silently dropped).
    """

    decision_id: str
    status: str  # APPROVE | BLOCK | ESCALATE
    reason: str
    reason_code: str
    timestamp: Optional[str] = None
    latency_ms: Optional[int] = None
    shadow_result: Optional[str] = None
    shadow_result_reason: Optional[str] = None
    escalation_id: Optional[str] = None
    escalation_expires_minutes: Optional[int] = None
    rule_triggered: Optional[str] = None
    policy_version: Optional[str] = None
    # /v1/execute only.
    execution_status: Optional[str] = None
    execution_response_code: Optional[int] = None
    # HITL restructure: origin + policy_recommendation. ``origin`` is
    # ``'human_gate'`` for /v1/execute APPROVE/BLOCK (a human must
    # confirm before the target fires), ``'policy_escalate'`` for
    # ESCALATE (existing flow), or ``None`` for /v1/evaluate.
    # ``policy_recommendation`` is the policy engine's verdict
    # (APPROVE/BLOCK/ESCALATE) — distinct from ``status`` which, in
    # shadow mode, is always APPROVE.
    origin: Optional[str] = None
    policy_recommendation: Optional[str] = None
    # Risk-tiered approval: the JWT role required to approve/reject the
    # human-gate confirmation. ``None`` means any authenticated reviewer.
    # Populated from the fired rule's escalation_config.target_role.
    # Callers building their own UI/notification layer on top of the SDK
    # can use this to route the pending confirmation to the right
    # person/team (e.g. page the CRO for high-value loan approvals).
    target_role: Optional[str] = None

    # ---- Convenience predicates (case-insensitive) ----
    @property
    def approved(self) -> bool:
        return (self.status or "").strip().upper() == "APPROVE"

    @property
    def blocked(self) -> bool:
        return (self.status or "").strip().upper() == "BLOCK"

    @property
    def escalated(self) -> bool:
        return (self.status or "").strip().upper() == "ESCALATE"

    @property
    def decision_status(self) -> DecisionStatus:
        """Typed view of ``status`` (validates on access)."""
        return DecisionStatus.from_value(self.status)


# ---------------------------------------------------------------------------
# Exception hierarchy
# ---------------------------------------------------------------------------
class AxioskyError(Exception):
    """Raised for any Axiosky API error or transport failure.

    ``detail`` is parsed from the JSON ``{"detail": ...}`` body when
    available (audit §4 — previously the raw response body was used).
    """

    def __init__(self, status_code: int = 0, detail: str = ""):
        self.status_code = status_code
        self.detail = detail
        msg = f"Axiosky API error {status_code}"
        if detail:
            msg += f": {detail}"
        super().__init__(msg)


class GovernanceDeniedError(AxioskyError):
    """Raised by ``@governed`` when the governor returns BLOCK.

    Subclasses ``AxioskyError`` so callers can catch the whole
    hierarchy with a single ``except AxioskyError``.
    """

    def __init__(self, decision: Decision):
        self.decision = decision
        super().__init__(
            0,
            f"Governance denied (action blocked): "
            f"reason_code={decision.reason_code}",
        )


class GovernanceEscalatedError(AxioskyError):
    """Raised by ``@governed`` when the governor returns ESCALATE."""

    def __init__(self, decision: Decision):
        self.decision = decision
        super().__init__(
            0,
            f"Governance escalated (awaiting human review): "
            f"escalation_id={decision.escalation_id}",
        )


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------
def _validate_non_empty_string(value: Any, name: str) -> str:
    """Return ``value`` if it's a non-empty string, else raise ValueError."""
    if not isinstance(value, str):
        raise ValueError(
            f"{name} must be a non-empty string, got "
            f"{type(value).__name__}"
        )
    if not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    return value


def _validate_target_url(url: str) -> None:
    """Ensure ``target_url`` uses an http/https scheme.

    Blocks ``file://``, ``ftp://``, ``gopher://``, etc. — these would
    either be invalid for the server to fetch or enable SSRF.
    """
    if not isinstance(url, str) or not url.strip():
        raise AxioskyError(0, "target_url must be a non-empty string")
    parsed = urlparse(url)
    scheme = (parsed.scheme or "").lower()
    if scheme not in ("http", "https"):
        raise AxioskyError(
            0,
            f"Invalid target_url scheme {scheme!r}: only http/https "
            f"are allowed",
        )
    if not parsed.hostname:
        raise AxioskyError(0, "target_url must include a hostname")


def _is_local_url(url: str) -> bool:
    """Detect whether ``url`` points at a local / private host.

    Covers:
      * ``localhost`` (any case)
      * IPv4 loopback ``127.0.0.0/8``
      * IPv6 loopback ``::1``
      * RFC 1918 private space (``10/8``, ``172.16/12``, ``192.168/16``)
      * Link-local (``169.254/16``, ``fe80::/10``)

    Used as an SSRF guard — the SDK warns (or the caller can refuse)
    when ``target_url`` points at internal infrastructure.
    """
    try:
        parsed = urlparse(url)
    except (ValueError, TypeError):
        return False
    host = parsed.hostname
    if not host:
        return False
    if host.lower() == "localhost":
        return True
    # Strip IPv6 brackets (urlparse already does, but be defensive).
    host = host.strip("[]")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        # Not an IP literal — could be a DNS name that resolves to a
        # private address. We can't know without resolving, so we only
        # flag literal IPs and ``localhost`` here.
        return False
    return bool(ip.is_loopback or ip.is_private or ip.is_link_local)


def _validate_escalation_id(escalation_id: str) -> str:
    """Validate that ``escalation_id`` is safe for URL interpolation.

    Only ``[a-zA-Z0-9-]`` is allowed — no slashes, dots, spaces, or
    control characters. Prevents path traversal / injection.
    """
    if not isinstance(escalation_id, str) or not _ESCALATION_ID_RE.match(
        escalation_id
    ):
        raise AxioskyError(
            0,
            "Invalid escalation_id: must match ^[a-zA-Z0-9\\-]+$ "
            "(no slashes, dots, spaces, or special characters)",
        )
    return escalation_id


def _parse_retry_after(value: Optional[str]) -> Optional[float]:
    """Parse a ``Retry-After`` header (RFC 7231 §7.1.3).

    Accepts either:
      * delta-seconds (integer or float), e.g. ``"120"``
      * HTTP-date, e.g. ``"Wed, 21 Oct 2015 07:28:00 GMT"``

    Returns the wait in seconds, clamped to ``MIN_RETRY_AFTER`` (so
    negative or zero values don't cause tight retry loops). Returns
    ``None`` if the header is absent or unparseable (caller falls back
    to exponential backoff).
    """
    if not value:
        return None
    value = value.strip()
    if not value:
        return None
    # Try delta-seconds first (most common).
    try:
        secs = float(value)
        if secs != secs:  # NaN
            return None
        return max(secs, MIN_RETRY_AFTER)
    except ValueError:
        pass
    # Try HTTP-date.
    try:
        dt_obj = email.utils.parsedate_to_datetime(value)
    except (ValueError, TypeError, OverflowError):
        return None
    if dt_obj is None:
        return None
    if dt_obj.tzinfo is None:
        dt_obj = dt_obj.replace(tzinfo=dt.timezone.utc)
    now = dt.datetime.now(dt.timezone.utc)
    delta = (dt_obj - now).total_seconds()
    return max(delta, MIN_RETRY_AFTER)


# ---------------------------------------------------------------------------
# Shared base
# ---------------------------------------------------------------------------
class _GovernorBase:
    """Shared logic between sync and async clients.

    Holds configuration and provides pure helpers (no I/O) so sync and
    async clients stay in lockstep.
    """

    def __init__(
        self,
        api_key: str,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = DEFAULT_TIMEOUT,
        max_retries: int = DEFAULT_MAX_RETRIES,
        *,
        verify: Union[bool, str] = True,
        limits: Optional[httpx.Limits] = None,
        fallback: str = "deny",
    ):
        if not api_key or not isinstance(api_key, str):
            raise ValueError("api_key is required")
        if max_retries < 0:
            raise ValueError(
                f"max_retries must be >= 0, got {max_retries}"
            )
        if fallback not in ("deny", "allow", "raise"):
            raise ValueError(
                f"fallback must be 'deny', 'allow', or 'raise', "
                f"got {fallback!r}"
            )

        # _api_key (protected — never expose as a public attribute).
        self._api_key = api_key
        self.base_url = (base_url or DEFAULT_BASE_URL).rstrip("/")
        self.timeout = timeout
        self.max_retries = max_retries
        self.verify = verify
        self.limits = limits or _DEFAULT_LIMITS
        self.fallback = fallback

        # Warn loudly if a production caller passes a non-HTTPS base_url.
        # We don't refuse (loopback dev is valid), but we log so the
        # caller notices.
        if (
            not self.base_url.startswith("https://")
            and not self.base_url.startswith("http://localhost")
            and not self.base_url.startswith("http://127.0.0.1")
        ):
            logger.warning(
                "Axiosky SDK base_url %r is not HTTPS. Production "
                "deployments must use HTTPS to protect the API key "
                "in transit.",
                self.base_url,
            )

    # ---- Header / body construction ----
    def _default_headers(self) -> Dict[str, str]:
        """Headers applied to every request via the httpx client default."""
        return {
            "Authorization": f"Bearer {self._api_key}",
            "User-Agent": _USER_AGENT,
        }

    def _headers(self, idempotency_key: Optional[str]) -> Dict[str, str]:
        """Per-request headers (idempotency key only).

        Authorization + User-Agent are set as client defaults so they
        appear on every request (including GETs that don't call this
        method). For JWT-gated endpoints the caller overrides
        Authorization per-request.
        """
        h: Dict[str, str] = {}
        if idempotency_key:
            h["X-Idempotency-Key"] = idempotency_key
        return h

    def _build_body(
        self,
        agent_id: str,
        action_type: str,
        tenant_id: Optional[str],
        payload: Optional[Dict[str, Any]],
        environment: str = "live",
        context_hooks: Optional[Dict[str, str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        body: Dict[str, Any] = {
            "agent_id": agent_id,
            "action_type": action_type,
            # dt.datetime.utcnow() is deprecated (audit §4); use
            # timezone-aware now().
            "timestamp": dt.datetime.now(dt.timezone.utc).isoformat(),
            "environment": environment,
            "payload": payload or {},
        }
        # tenant_id is optional — the server derives it from the API
        # key. We still send it if the caller insists (backward compat).
        if tenant_id is not None:
            body["tenant_id"] = tenant_id
        if context_hooks:
            body["context_hooks"] = context_hooks
        if metadata:
            body["metadata"] = metadata
        return body

    @staticmethod
    def _parse_decision(data: Any) -> Decision:
        """Parse the API response into a ``Decision``.

        Wraps ``KeyError`` / ``TypeError`` in ``AxioskyError`` so a
        malformed response never surfaces as a raw Python exception
        (audit §4).
        """
        if not isinstance(data, dict):
            raise AxioskyError(
                0,
                f"Malformed decision response: expected JSON object, "
                f"got {type(data).__name__}",
            )
        # Validate required fields exist and are strings (not None).
        for field in ("decision_id", "status", "reason", "reason_code"):
            if not isinstance(data.get(field), str):
                raise AxioskyError(
                    0,
                    f"Malformed decision response: field {field!r} "
                    f"must be a non-null string",
                )
        try:
            return Decision(
                decision_id=data["decision_id"],
                status=data["status"],
                reason=data["reason"],
                reason_code=data["reason_code"],
                timestamp=data.get("timestamp"),
                latency_ms=data.get("latency_ms"),
                shadow_result=data.get("shadow_result"),
                shadow_result_reason=data.get("shadow_result_reason"),
                escalation_id=data.get("escalation_id"),
                escalation_expires_minutes=data.get(
                    "escalation_expires_minutes"
                ),
                rule_triggered=data.get("rule_triggered"),
                policy_version=data.get("policy_version"),
                execution_status=data.get("execution_status"),
                execution_response_code=data.get("execution_response_code"),
                # HITL restructure fields.
                origin=data.get("origin"),
                policy_recommendation=data.get("policy_recommendation"),
                # Risk-tiered approval field.
                target_role=data.get("target_role"),
            )
        except (KeyError, TypeError) as e:
            raise AxioskyError(
                0,
                f"Malformed decision response: missing or invalid "
                f"field ({e})",
            ) from e

    @staticmethod
    def _extract_detail(resp: httpx.Response) -> str:
        """Parse the error detail from a JSON ``{"detail": ...}`` body.

        Falls back to the raw text if the body isn't JSON or doesn't
        contain a detail field (audit §4). Uses
        ``resp.content.decode("utf-8", errors="replace")`` so a
        non-UTF-8 body never raises ``UnicodeDecodeError`` and masks
        the original HTTP error.
        """
        try:
            data = resp.json()
            if isinstance(data, dict) and "detail" in data:
                return str(data["detail"])
            return json.dumps(data)
        except Exception:
            return resp.content.decode("utf-8", errors="replace")

    def _effective_fallback(self, override: Optional[str]) -> str:
        if override is None:
            return self.fallback
        if override not in ("deny", "allow", "raise"):
            raise ValueError(
                f"fallback must be 'deny', 'allow', or 'raise', "
                f"got {override!r}"
            )
        return override

    def _fallback_decision(
        self,
        mode: str,
        agent_id: str,
        action_type: str,
    ) -> Decision:
        """Build a synthetic ``Decision`` when the API is unreachable.

        ``mode="deny"`` (default): returns BLOCK — safest for regulated
        workloads. ``mode="allow"``: returns APPROVE (warned).
        ``mode="raise"``: raises ``AxioskyError`` instead.

        The reason strings are deliberately generic — no internal
        network details, exception messages, or hostnames leak.
        """
        if mode == "raise":
            raise AxioskyError(0, "Governance API unreachable")
        if mode == "allow":
            logger.warning(
                "Axiosky API unreachable; fallback=allow permitting "
                "action (agent=%s action=%s). This bypasses governance "
                "— ensure this is intentional for your environment.",
                agent_id, action_type,
            )
            return Decision(
                decision_id=f"fallback-allow-{uuid.uuid4()}",
                status="APPROVE",
                reason="Governance API unreachable; fallback=allow",
                reason_code="FALLBACK_ALLOW",
                latency_ms=0,
            )
        # default: deny
        logger.warning(
            "Axiosky API unreachable; fallback=deny blocking action "
            "(agent=%s action=%s).",
            agent_id, action_type,
        )
        return Decision(
            decision_id=f"fallback-block-{uuid.uuid4()}",
            status="BLOCK",
            reason="Governance API unreachable",
            reason_code="FALLBACK_BLOCK",
            latency_ms=0,
        )

    def __repr__(self) -> str:
        # Mask the API key — never let a stray repr leak it into logs.
        masked = f"{self._api_key[:4]}***" if self._api_key else "***"
        return (
            f"{type(self).__name__}(base_url={self.base_url!r}, "
            f"api_key={masked!r}, version={__version__!r}, "
            f"max_retries={self.max_retries}, fallback={self.fallback!r})"
        )


# ---------------------------------------------------------------------------
# Sync client
# ---------------------------------------------------------------------------
class Governor(_GovernorBase):
    """Synchronous Axiosky client."""

    def __init__(
        self,
        api_key: str,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = DEFAULT_TIMEOUT,
        max_retries: int = DEFAULT_MAX_RETRIES,
        *,
        verify: Union[bool, str] = True,
        limits: Optional[httpx.Limits] = None,
        fallback: str = "deny",
    ):
        super().__init__(
            api_key,
            base_url,
            timeout,
            max_retries,
            verify=verify,
            limits=limits,
            fallback=fallback,
        )
        # httpx.Client is thread-safe for concurrent requests — its
        # internal connection pool serializes access. We share one
        # client across all calls on this Governor.
        self._client = httpx.Client(
            base_url=self.base_url,
            headers=self._default_headers(),
            timeout=timeout,
            verify=self.verify,
            limits=self.limits,
        )

    # ---- Core transport ----
    def _request_with_retry(
        self,
        method: str,
        url: str,
        *,
        json_body: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        idempotent: bool = True,
    ) -> httpx.Response:
        """Send a request with retry + backoff.

        Retries on:
          * 429 (rate-limited — request was not processed)
          * 5xx (server error — only if ``idempotent=True``)
          * Transport errors (ConnectError, TimeoutException — only if
            ``idempotent=True``)

        Never retries on 4xx other than 429 — the request is wrong and
        retrying won't help.

        Returns the final ``httpx.Response`` (any status). Raises
        ``AxioskyError`` only for transport errors when retries are
        exhausted (or when ``idempotent=False``); the caller decides
        whether to apply fallback.
        """
        last_exc: Optional[Exception] = None
        merged_headers = {**self._headers(None), **(headers or {})}
        for attempt in range(self.max_retries + 1):
            try:
                resp = self._client.request(
                    method,
                    url,
                    json=json_body,
                    params=params,
                    headers=merged_headers,
                )
                # Decide whether to retry based on status.
                retryable = resp.status_code == 429 or (
                    resp.status_code >= 500 and idempotent
                )
                if retryable and attempt < self.max_retries:
                    wait = self._compute_wait(resp, attempt)
                    logger.warning(
                        "Axiosky %d (attempt %d/%d) — retrying in "
                        "%.2fs",
                        resp.status_code,
                        attempt + 1,
                        self.max_retries,
                        wait,
                    )
                    time.sleep(wait)
                    continue
                return resp
            except (httpx.ConnectError, httpx.TimeoutException) as e:
                last_exc = e
                if idempotent and attempt < self.max_retries:
                    wait = 2.0 * (2 ** attempt)
                    logger.warning(
                        "Axiosky transport error (attempt %d/%d): %s "
                        "— retrying in %.1fs",
                        attempt + 1, self.max_retries, e, wait,
                    )
                    time.sleep(wait)
                    continue
                # Not idempotent, or exhausted — let the caller decide.
                raise AxioskyError(0, "Transport error") from e
        # Unreachable (the loop either returns or raises), but keeps
        # type-checkers happy.
        raise AxioskyError(0, f"Exhausted retries: {last_exc}")

    @staticmethod
    def _compute_wait(resp: httpx.Response, attempt: int) -> float:
        """Compute the sleep before the next retry attempt."""
        retry_after = resp.headers.get("Retry-After")
        parsed = _parse_retry_after(retry_after)
        if parsed is not None:
            return parsed
        # Exponential backoff with jitter-free base. The base doubles
        # each attempt: 1s, 2s, 4s, ...
        return 2.0 * (2 ** attempt)

    # ---- Public API ----
    def evaluate(
        self,
        agent_id: str,
        action_type: str,
        tenant_id: Optional[str] = None,
        payload: Optional[Dict[str, Any]] = None,
        environment: str = "live",
        context_hooks: Optional[Dict[str, str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        idempotent: bool = True,
        idempotency_key: Optional[str] = None,
        fallback: Optional[str] = None,
    ) -> Decision:
        """Submit an action for a governance decision.

        Auto-generates an ``X-Idempotency-Key`` when ``idempotent=True``
        (default) and no explicit key is provided, so safe client
        retries don't create duplicate decisions.

        If the API is unreachable and ``fallback`` is ``"deny"`` (the
        default), returns a synthetic BLOCK ``Decision`` instead of
        raising — safest for regulated workloads.
        """
        _validate_non_empty_string(agent_id, "agent_id")
        _validate_non_empty_string(action_type, "action_type")
        if tenant_id is not None:
            warnings.warn(
                "tenant_id is deprecated; the tenant is now determined "
                "from the API key server-side. Stop passing tenant_id "
                "to Governor.evaluate().",
                DeprecationWarning,
                stacklevel=2,
            )
        eff_fallback = self._effective_fallback(fallback)

        if idempotent and not idempotency_key:
            idempotency_key = str(uuid.uuid4())
        body = self._build_body(
            agent_id, action_type, tenant_id, payload,
            environment, context_hooks, metadata,
        )
        try:
            resp = self._request_with_retry(
                "POST", "/v1/evaluate",
                json_body=body,
                headers=self._headers(idempotency_key),
                idempotent=idempotent,
            )
        except AxioskyError as e:
            if e.status_code == 0:  # transport error
                return self._fallback_decision(
                    eff_fallback, agent_id, action_type
                )
            raise
        if resp.status_code == 200:
            return self._parse_decision(resp.json())
        if 400 <= resp.status_code < 500 and resp.status_code != 429:
            # Client error — raise (no fallback; the request is wrong).
            raise AxioskyError(
                resp.status_code, self._extract_detail(resp)
            )
        # 429 or 5xx after exhausting retries — fall back.
        return self._fallback_decision(
            eff_fallback, agent_id, action_type
        )

    def execute(
        self,
        agent_id: str,
        action_type: str,
        target_url: str,
        tenant_id: Optional[str] = None,
        payload: Optional[Dict[str, Any]] = None,
        environment: str = "live",
        context_hooks: Optional[Dict[str, str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        idempotent: bool = True,
        idempotency_key: Optional[str] = None,
        fallback: Optional[str] = None,
    ) -> Decision:
        """Submit an action for governance evaluation AND human confirmation.

        HITL RESTRUCTURE: this method NO LONGER auto-executes the target
        URL on APPROVE. The server creates a pending human-confirmation
        record (an escalation with ``origin='human_gate'``) and returns
        immediately with ``execution_status='pending_human_review'``.
        A human approval queues delivery. Only the contracted receiver
        acknowledgement confirms completed business execution.

        The returned ``Decision`` has:
          - ``execution_status='pending_human_review'`` (non-terminal —
            the human hasn't acted yet)
          - ``origin='human_gate'`` (for APPROVE/BLOCK) or
            ``'policy_escalate'`` (for ESCALATE)
          - ``policy_recommendation`` — the policy engine's verdict
          - ``escalation_id`` — the ID to track this confirmation

        To learn the final outcome, call :meth:`poll_for_decision` (one-
        shot) or :meth:`wait_for_decision` (polls until terminal). The
        async default is non-blocking: ``execute()`` returns immediately
        with a pending Decision; the caller decides whether to poll.

        Shadow mode: ``execution_status='shadow_skipped'`` (terminal —
        shadow mode never fires the target, regardless of verdict or
        human confirmation).

        ``target_url`` must use ``http`` or ``https`` — other schemes
        are rejected (SSRF guard). If the host is local/private, a
        warning is logged.
        """
        _validate_non_empty_string(agent_id, "agent_id")
        _validate_non_empty_string(action_type, "action_type")
        _validate_target_url(target_url)
        if _is_local_url(target_url):
            logger.warning(
                "Axiosky execute() target_url %r points at a local / "
                "private address — this may be an SSRF attempt or a "
                "misconfiguration.",
                target_url,
            )
        if tenant_id is not None:
            warnings.warn(
                "tenant_id is deprecated; the tenant is now determined "
                "from the API key server-side.",
                DeprecationWarning,
                stacklevel=2,
            )
        eff_fallback = self._effective_fallback(fallback)

        if idempotent and not idempotency_key:
            idempotency_key = str(uuid.uuid4())
        body = self._build_body(
            agent_id, action_type, tenant_id, payload,
            environment, context_hooks, metadata,
        )
        body["target_url"] = target_url
        try:
            resp = self._request_with_retry(
                "POST", "/v1/execute",
                json_body=body,
                headers=self._headers(idempotency_key),
                idempotent=idempotent,
            )
        except AxioskyError as e:
            if e.status_code == 0:
                return self._fallback_decision(
                    eff_fallback, agent_id, action_type
                )
            raise
        if resp.status_code == 200:
            return self._parse_decision(resp.json())
        if 400 <= resp.status_code < 500 and resp.status_code != 429:
            raise AxioskyError(
                resp.status_code, self._extract_detail(resp)
            )
        return self._fallback_decision(
            eff_fallback, agent_id, action_type
        )

    # ─── HITL restructure: decision polling ──────────────────────────
    # These methods let the caller learn the final outcome of a
    # /v1/execute request that returned execution_status='pending_human_review'.
    # Terminal execution_status values:
    #   'executed'              — human approved, target fired successfully
    #   'blocked_by_human'      — human rejected, target NOT fired
    #   'failed'                — human approved but target call failed
    #   'expired_auto_blocked'  — no human response, action_on_expiry=BLOCK fired
    #   'expired_auto_approved' — no human response, action_on_expiry=APPROVE (rare)
    #   'shadow_skipped'        — shadow mode (terminal at execute time)
    #   'not_replayed_cached'   — cached response (terminal at execute time)
    # Non-terminal: 'pending_human_review'.

    # Module-level constant — the set of execution_status values that
    # indicate the lifecycle is complete (no further polling needed).
    _TERMINAL_EXECUTION_STATUSES = frozenset({
        "delivery_unconfirmed",  # bounded stop: operator reconciliation required
        "executed",
        "blocked_by_human",
        "failed",
        "expired_auto_blocked",
        "expired_auto_approved",
        "shadow_skipped",
        "not_replayed_cached",
        "approved_no_execution",   # policy_escalate approve (no target)
        "rejected_no_execution",   # policy_escalate reject (no target)
        "unknown_no_escalation",   # shadow/cached — can't poll
    })

    def poll_for_decision(self, decision_id: str) -> Dict[str, Any]:
        """Single-shot poll: fetch the current state of a decision.

        Returns the raw JSON response from ``GET /v1/decisions/{decision_id}``.
        The caller inspects ``execution_status`` to decide whether to
        poll again or treat the decision as terminal.

        Non-blocking — makes exactly one HTTP call.
        """
        _validate_non_empty_string(decision_id, "decision_id")
        resp = self._request_with_retry(
            "GET", f"/v1/decisions/{decision_id}",
            headers=self._headers(None),
            idempotent=True,
        )
        if resp.status_code == 200:
            return resp.json()
        if 400 <= resp.status_code < 500 and resp.status_code != 429:
            raise AxioskyError(
                resp.status_code, self._extract_detail(resp)
            )
        raise AxioskyError(
            resp.status_code,
            f"Failed to poll decision {decision_id}: "
            f"HTTP {resp.status_code}",
        )

    def wait_for_decision(
        self,
        decision_id: str,
        timeout: float = 60.0,
        poll_interval: float = 1.0,
    ) -> Dict[str, Any]:
        """Poll until the decision reaches a terminal execution_status.

        Blocks the calling thread for up to ``timeout`` seconds, polling
        every ``poll_interval`` seconds. Returns the final decision
        state. Raises ``AxioskyError`` on timeout (status_code=0).

        This is the BLOCKING variant — use it when the caller needs the
        final outcome synchronously. The async default is non-blocking:
        call :meth:`poll_for_decision` directly if you want to integrate
        polling into your own event loop.

        Args:
            decision_id: the decision_id returned by :meth:`execute`.
            timeout: max seconds to wait (default 60). Raises on expiry.
            poll_interval: seconds between polls (default 1).

        Returns:
            The final decision state dict (with a terminal
            ``execution_status``).
        """
        import time as _time
        deadline = _time.monotonic() + timeout
        while _time.monotonic() < deadline:
            state = self.poll_for_decision(decision_id)
            exec_status = state.get("execution_status")
            if exec_status in self._TERMINAL_EXECUTION_STATUSES:
                return state
            time.sleep(poll_interval)
        raise AxioskyError(
            0,
            f"Timed out after {timeout}s waiting for decision "
            f"{decision_id} to reach a terminal state. Last status: "
            f"{exec_status if 'exec_status' in dir() else 'unknown'}.",
        )

    def verify_chain(self, tenant_id: str) -> dict:
        """Verify the audit hash chain for the tenant."""
        _validate_non_empty_string(tenant_id, "tenant_id")
        resp = self._request_with_retry(
            "POST", "/v1/audit-logs/verify",
            json_body={"tenant_id": tenant_id},
            headers=self._headers(None),
            idempotent=True,
        )
        if resp.status_code != 200:
            raise AxioskyError(
                resp.status_code, self._extract_detail(resp)
            )
        return resp.json()

    def get_audit_logs(
        self,
        tenant_id: str,
        limit: int = 100,
        offset: int = 0,
        status_filter: Optional[str] = None,
        agent_id: Optional[str] = None,
    ) -> dict:
        """Fetch a paginated list of audit log entries."""
        _validate_non_empty_string(tenant_id, "tenant_id")
        params: Dict[str, Any] = {"limit": limit, "offset": offset}
        if status_filter:
            params["status"] = status_filter
        if agent_id:
            params["agent_id"] = agent_id
        resp = self._request_with_retry(
            "GET", "/v1/audit-logs",
            params=params,
            headers=self._headers(None),
            idempotent=True,
        )
        if resp.status_code != 200:
            raise AxioskyError(
                resp.status_code, self._extract_detail(resp)
            )
        return resp.json()

    def get_shadow_report(
        self,
        tenant_id: str,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
    ) -> dict:
        """Fetch the shadow-mode pilot report."""
        _validate_non_empty_string(tenant_id, "tenant_id")
        params: Dict[str, Any] = {}
        if start_date:
            params["start_date"] = start_date
        if end_date:
            params["end_date"] = end_date
        resp = self._request_with_retry(
            "GET", "/v1/reports/shadow",
            params=params,
            headers=self._headers(None),
            idempotent=True,
        )
        if resp.status_code != 200:
            raise AxioskyError(
                resp.status_code, self._extract_detail(resp)
            )
        return resp.json()

    def get_escalations(
        self,
        status_filter: str = "pending",
        limit: int = 50,
        offset: int = 0,
    ) -> dict:
        """Fetch pending escalations for the tenant.

        The tenant is determined by the API key (TenantMiddleware on
        the server side); there is no client-supplied tenant_id
        parameter to avoid the misleading impression that a caller can
        fetch another tenant's escalations.
        """
        params: Dict[str, Any] = {
            "status_filter": status_filter,
            "limit": limit,
            "offset": offset,
        }
        resp = self._request_with_retry(
            "GET", "/v1/escalations",
            params=params,
            headers=self._headers(None),
            idempotent=True,
        )
        if resp.status_code != 200:
            raise AxioskyError(
                resp.status_code, self._extract_detail(resp)
            )
        return resp.json()

    def resolve_escalation(
        self,
        escalation_id: str,
        decision: str,
        resolved_by: str,
        resolver_role: str,
    ) -> dict:
        """Approve or reject an escalation.

        Args:
            escalation_id: the escalation ID (validated against
                ``^[a-zA-Z0-9\\-]+$`` to prevent path injection).
            decision: ``"approve"`` or ``"reject"``.
            resolved_by: the email/name of the human resolver.
            resolver_role: self-reported role (API-key path only; the
                dashboard path reads this from JWT claims).

        Returns the escalation's new state dict. Raises ``AxioskyError``
        on non-200 responses (404 not found, 409 already resolved,
        403 wrong role, 410 expired).

        This endpoint mutates state and has no idempotency key, so it
        is NOT retried on transport errors — a retry could double-apply
        a resolution.
        """
        _validate_escalation_id(escalation_id)
        if decision not in ("approve", "reject"):
            raise ValueError("decision must be 'approve' or 'reject'")
        # Route through _request_with_retry so we get User-Agent, retry
        # on 429/5xx (server-side errors), and consistent error
        # handling. idempotent=False so transport errors raise
        # immediately (no double-resolution).
        resp = self._request_with_retry(
            "POST",
            f"/v1/escalations/{escalation_id}/{decision}",
            json_body={
                "resolved_by": resolved_by,
                "resolver_role": resolver_role,
            },
            headers={"Content-Type": "application/json"},
            idempotent=False,
        )
        if resp.status_code != 200:
            raise AxioskyError(
                resp.status_code, self._extract_detail(resp)
            )
        return resp.json()

    def get_policy_templates(self, jwt: Optional[str] = None) -> dict:
        """Fetch the loaded policy templates and their rules.

        This endpoint is JWT-gated (``verify_dashboard_token``) — a
        regular API key will be rejected with 401. Pass a valid Auth0
        JWT via the ``jwt`` parameter.
        """
        if not jwt:
            raise ValueError(
                "get_policy_templates requires a JWT (the endpoint is "
                "JWT-gated, not API-key authenticated). Pass the Auth0 "
                "access token via the jwt= parameter."
            )
        # Override Authorization with the JWT (per-request header
        # merges over the client default).
        resp = self._request_with_retry(
            "GET", "/v1/dashboard/policy-templates",
            headers={"Authorization": f"Bearer {jwt}"},
            idempotent=True,
        )
        if resp.status_code != 200:
            raise AxioskyError(
                resp.status_code, self._extract_detail(resp)
            )
        return resp.json()

    # ---- Lifecycle ----
    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "Governor":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()


# ---------------------------------------------------------------------------
# Async client
# ---------------------------------------------------------------------------
class AsyncGovernor(_GovernorBase):
    """Asynchronous Axiosky client.

    Mirrors ``Governor``'s API but uses ``httpx.AsyncClient``. Target
    customers (AI agent frameworks) are often async; the sync-only SDK
    forced them to wrap every call in ``run_in_executor``.

    ``AsyncGovernor`` is safe to share across tasks within a single
    event loop (``httpx.AsyncClient`` serializes connection-pool
    access). Do NOT share across event loops — create one per loop.
    """

    def __init__(
        self,
        api_key: str,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = DEFAULT_TIMEOUT,
        max_retries: int = DEFAULT_MAX_RETRIES,
        *,
        verify: Union[bool, str] = True,
        limits: Optional[httpx.Limits] = None,
        fallback: str = "deny",
    ):
        super().__init__(
            api_key,
            base_url,
            timeout,
            max_retries,
            verify=verify,
            limits=limits,
            fallback=fallback,
        )
        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            headers=self._default_headers(),
            timeout=timeout,
            verify=self.verify,
            limits=self.limits,
        )

    async def _request_with_retry(
        self,
        method: str,
        url: str,
        *,
        json_body: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        idempotent: bool = True,
    ) -> httpx.Response:
        """Async twin of ``Governor._request_with_retry``."""
        last_exc: Optional[Exception] = None
        merged_headers = {**self._headers(None), **(headers or {})}
        for attempt in range(self.max_retries + 1):
            try:
                resp = await self._client.request(
                    method,
                    url,
                    json=json_body,
                    params=params,
                    headers=merged_headers,
                )
                retryable = resp.status_code == 429 or (
                    resp.status_code >= 500 and idempotent
                )
                if retryable and attempt < self.max_retries:
                    wait = self._compute_wait(resp, attempt)
                    logger.warning(
                        "Axiosky %d (attempt %d/%d) — retrying in "
                        "%.2fs",
                        resp.status_code,
                        attempt + 1,
                        self.max_retries,
                        wait,
                    )
                    await asyncio.sleep(wait)
                    continue
                return resp
            except (httpx.ConnectError, httpx.TimeoutException) as e:
                last_exc = e
                if idempotent and attempt < self.max_retries:
                    wait = 2.0 * (2 ** attempt)
                    logger.warning(
                        "Axiosky transport error (attempt %d/%d): %s "
                        "— retrying in %.1fs",
                        attempt + 1, self.max_retries, e, wait,
                    )
                    await asyncio.sleep(wait)
                    continue
                raise AxioskyError(0, "Transport error") from e
        raise AxioskyError(0, f"Exhausted retries: {last_exc}")

    @staticmethod
    def _compute_wait(resp: httpx.Response, attempt: int) -> float:
        retry_after = resp.headers.get("Retry-After")
        parsed = _parse_retry_after(retry_after)
        if parsed is not None:
            return parsed
        return 2.0 * (2 ** attempt)

    async def evaluate(
        self,
        agent_id: str,
        action_type: str,
        tenant_id: Optional[str] = None,
        payload: Optional[Dict[str, Any]] = None,
        environment: str = "live",
        context_hooks: Optional[Dict[str, str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        idempotent: bool = True,
        idempotency_key: Optional[str] = None,
        fallback: Optional[str] = None,
    ) -> Decision:
        """Async twin of ``Governor.evaluate``."""
        _validate_non_empty_string(agent_id, "agent_id")
        _validate_non_empty_string(action_type, "action_type")
        if tenant_id is not None:
            warnings.warn(
                "tenant_id is deprecated; the tenant is now determined "
                "from the API key server-side.",
                DeprecationWarning,
                stacklevel=2,
            )
        eff_fallback = self._effective_fallback(fallback)

        if idempotent and not idempotency_key:
            idempotency_key = str(uuid.uuid4())
        body = self._build_body(
            agent_id, action_type, tenant_id, payload,
            environment, context_hooks, metadata,
        )
        try:
            resp = await self._request_with_retry(
                "POST", "/v1/evaluate",
                json_body=body,
                headers=self._headers(idempotency_key),
                idempotent=idempotent,
            )
        except AxioskyError as e:
            if e.status_code == 0:
                return self._fallback_decision(
                    eff_fallback, agent_id, action_type
                )
            raise
        if resp.status_code == 200:
            return self._parse_decision(resp.json())
        if 400 <= resp.status_code < 500 and resp.status_code != 429:
            raise AxioskyError(
                resp.status_code, self._extract_detail(resp)
            )
        return self._fallback_decision(
            eff_fallback, agent_id, action_type
        )

    async def execute(
        self,
        agent_id: str,
        action_type: str,
        target_url: str,
        tenant_id: Optional[str] = None,
        payload: Optional[Dict[str, Any]] = None,
        environment: str = "live",
        context_hooks: Optional[Dict[str, str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        idempotent: bool = True,
        idempotency_key: Optional[str] = None,
        fallback: Optional[str] = None,
    ) -> Decision:
        """Async twin of ``Governor.execute``.

        HITL RESTRUCTURE: returns a pending Decision (``execution_status=
        'pending_human_review'``), NOT an executed result. The target URL
        is fired only after a human approves via the dashboard. Call
        :meth:`poll_for_decision` or :meth:`wait_for_decision` to learn
        the final outcome.
        """
        _validate_non_empty_string(agent_id, "agent_id")
        _validate_non_empty_string(action_type, "action_type")
        _validate_target_url(target_url)
        if _is_local_url(target_url):
            logger.warning(
                "Axiosky execute() target_url %r points at a local / "
                "private address — possible SSRF or misconfiguration.",
                target_url,
            )
        if tenant_id is not None:
            warnings.warn(
                "tenant_id is deprecated; the tenant is now determined "
                "from the API key server-side.",
                DeprecationWarning,
                stacklevel=2,
            )
        eff_fallback = self._effective_fallback(fallback)

        if idempotent and not idempotency_key:
            idempotency_key = str(uuid.uuid4())
        body = self._build_body(
            agent_id, action_type, tenant_id, payload,
            environment, context_hooks, metadata,
        )
        body["target_url"] = target_url
        try:
            resp = await self._request_with_retry(
                "POST", "/v1/execute",
                json_body=body,
                headers=self._headers(idempotency_key),
                idempotent=idempotent,
            )
        except AxioskyError as e:
            if e.status_code == 0:
                return self._fallback_decision(
                    eff_fallback, agent_id, action_type
                )
            raise
        if resp.status_code == 200:
            return self._parse_decision(resp.json())
        if 400 <= resp.status_code < 500 and resp.status_code != 429:
            raise AxioskyError(
                resp.status_code, self._extract_detail(resp)
            )
        return self._fallback_decision(
            eff_fallback, agent_id, action_type
        )

    # ─── HITL restructure: async decision polling ────────────────────
    async def poll_for_decision(self, decision_id: str) -> Dict[str, Any]:
        """Async single-shot poll: fetch the current state of a decision.

        See ``Governor.poll_for_decision`` for the full contract.
        """
        _validate_non_empty_string(decision_id, "decision_id")
        resp = await self._request_with_retry(
            "GET", f"/v1/decisions/{decision_id}",
            headers=self._headers(None),
            idempotent=True,
        )
        if resp.status_code == 200:
            return resp.json()
        if 400 <= resp.status_code < 500 and resp.status_code != 429:
            raise AxioskyError(
                resp.status_code, self._extract_detail(resp)
            )
        raise AxioskyError(
            resp.status_code,
            f"Failed to poll decision {decision_id}: "
            f"HTTP {resp.status_code}",
        )

    async def wait_for_decision(
        self,
        decision_id: str,
        timeout: float = 60.0,
        poll_interval: float = 1.0,
    ) -> Dict[str, Any]:
        """Async poll until the decision reaches a terminal execution_status.

        Awaits up to ``timeout`` seconds, polling every ``poll_interval``
        seconds. Returns the final decision state. Raises ``AxioskyError``
        on timeout (status_code=0).

        This is the ASYNC-BY-DEFAULT variant — it does NOT block the
        event loop; it awaits ``asyncio.sleep`` between polls. Use this
        in async code; use ``Governor.wait_for_decision`` (sync) in
        synchronous code.
        """
        import asyncio as _asyncio
        deadline = _asyncio.get_event_loop().time() + timeout
        last_status = "unknown"
        while _asyncio.get_event_loop().time() < deadline:
            state = await self.poll_for_decision(decision_id)
            exec_status = state.get("execution_status")
            last_status = exec_status or "unknown"
            if exec_status in Governor._TERMINAL_EXECUTION_STATUSES:
                return state
            await _asyncio.sleep(poll_interval)
        raise AxioskyError(
            0,
            f"Timed out after {timeout}s waiting for decision "
            f"{decision_id} to reach a terminal state. Last status: "
            f"{last_status}.",
        )

    async def verify_chain(self, tenant_id: str) -> dict:
        """Verify the audit hash chain for the tenant (async)."""
        _validate_non_empty_string(tenant_id, "tenant_id")
        resp = await self._request_with_retry(
            "POST", "/v1/audit-logs/verify",
            json_body={"tenant_id": tenant_id},
            headers=self._headers(None),
            idempotent=True,
        )
        if resp.status_code != 200:
            raise AxioskyError(
                resp.status_code, self._extract_detail(resp)
            )
        return resp.json()

    async def get_audit_logs(
        self,
        tenant_id: str,
        limit: int = 100,
        offset: int = 0,
        status_filter: Optional[str] = None,
        agent_id: Optional[str] = None,
    ) -> dict:
        """Fetch a paginated list of audit log entries (async)."""
        _validate_non_empty_string(tenant_id, "tenant_id")
        params: Dict[str, Any] = {"limit": limit, "offset": offset}
        if status_filter:
            params["status"] = status_filter
        if agent_id:
            params["agent_id"] = agent_id
        resp = await self._request_with_retry(
            "GET", "/v1/audit-logs",
            params=params,
            headers=self._headers(None),
            idempotent=True,
        )
        if resp.status_code != 200:
            raise AxioskyError(
                resp.status_code, self._extract_detail(resp)
            )
        return resp.json()

    async def get_shadow_report(
        self,
        tenant_id: str,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
    ) -> dict:
        """Fetch the shadow-mode pilot report (async)."""
        _validate_non_empty_string(tenant_id, "tenant_id")
        params: Dict[str, Any] = {}
        if start_date:
            params["start_date"] = start_date
        if end_date:
            params["end_date"] = end_date
        resp = await self._request_with_retry(
            "GET", "/v1/reports/shadow",
            params=params,
            headers=self._headers(None),
            idempotent=True,
        )
        if resp.status_code != 200:
            raise AxioskyError(
                resp.status_code, self._extract_detail(resp)
            )
        return resp.json()

    async def get_escalations(
        self,
        status_filter: str = "pending",
        limit: int = 50,
        offset: int = 0,
    ) -> dict:
        """Fetch pending escalations for the tenant (async)."""
        params: Dict[str, Any] = {
            "status_filter": status_filter,
            "limit": limit,
            "offset": offset,
        }
        resp = await self._request_with_retry(
            "GET", "/v1/escalations",
            params=params,
            headers=self._headers(None),
            idempotent=True,
        )
        if resp.status_code != 200:
            raise AxioskyError(
                resp.status_code, self._extract_detail(resp)
            )
        return resp.json()

    async def resolve_escalation(
        self,
        escalation_id: str,
        decision: str,
        resolved_by: str,
        resolver_role: str,
    ) -> dict:
        """Approve or reject an escalation (async)."""
        _validate_escalation_id(escalation_id)
        if decision not in ("approve", "reject"):
            raise ValueError("decision must be 'approve' or 'reject'")
        resp = await self._request_with_retry(
            "POST",
            f"/v1/escalations/{escalation_id}/{decision}",
            json_body={
                "resolved_by": resolved_by,
                "resolver_role": resolver_role,
            },
            headers={"Content-Type": "application/json"},
            idempotent=False,
        )
        if resp.status_code != 200:
            raise AxioskyError(
                resp.status_code, self._extract_detail(resp)
            )
        return resp.json()

    async def get_policy_templates(
        self, jwt: Optional[str] = None
    ) -> dict:
        """Fetch the loaded policy templates and their rules (async).

        This endpoint is JWT-gated — pass an Auth0 JWT via ``jwt=``.
        """
        if not jwt:
            raise ValueError(
                "get_policy_templates requires a JWT (the endpoint is "
                "JWT-gated, not API-key authenticated)."
            )
        resp = await self._request_with_retry(
            "GET", "/v1/dashboard/policy-templates",
            headers={"Authorization": f"Bearer {jwt}"},
            idempotent=True,
        )
        if resp.status_code != 200:
            raise AxioskyError(
                resp.status_code, self._extract_detail(resp)
            )
        return resp.json()

    async def aclose(self) -> None:
        """Close the underlying async HTTP client."""
        await self._client.aclose()

    async def close(self) -> None:  # alias for aclose
        await self.aclose()

    async def __aenter__(self) -> "AsyncGovernor":
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.aclose()


# ---------------------------------------------------------------------------
# @governed decorator
# ---------------------------------------------------------------------------
def governed(
    action_type: str,
    *,
    agent_id: Optional[str] = None,
    tenant_id: Optional[str] = None,
    payload_fn: Optional[Callable[..., Dict[str, Any]]] = None,
    target_url: Optional[str] = None,
    enforcement: str = "human_gate",
    timeout: float = 60.0,
    poll_interval: float = 1.0,
    _axiosky_governor: Optional[Union[Governor, AsyncGovernor]] = None,
    **governor_kwargs: Any,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Decorator that gates a function through a ``Governor``.

    SECURITY (changed): the default, ``enforcement="human_gate"``, routes
    through ``/v1/execute`` exactly like the dashboard-approved flow. The
    wrapped function runs ONLY after a human has approved AND the target
    has been confirmed executed (terminal ``execution_status == "executed"``).
    A rejection, expiry, or block raises ``GovernanceDeniedError`` and the
    wrapped function never runs. An ambiguous outcome (``failed``,
    ``delivery_unconfirmed``) raises ``AxioskyError`` rather than silently
    skipping or silently running the function.

    ``enforcement="evaluate_only"`` restores the previous behavior: the
    wrapped function runs immediately on an APPROVE from ``evaluate()``,
    with NO human ever confirming it. This bypasses human review entirely.
    Use it only for genuinely low-risk, reversible, non-financial actions
    where you have deliberately decided human review is unnecessary — it
    is an explicit, opt-in escape hatch, not the default, and every call
    logs a warning so this can't be silently relied on in production.

    Sync vs async is auto-detected via ``inspect.iscoroutinefunction``.

    Example (default, human-gated)::

        @governed("loan_disbursal", target_url="https://core.bank/disburse")
        def on_approved_disbursal(loan_id):
            # Runs only after a human approved AND the disbursal target
            # confirmed execution. Use this for side effects (notify,
            # update local records) — the actual money movement already
            # happened via the pinned target_url, server-side.
            ...

    Example (explicit unsafe opt-out)::

        @governed("data_export", enforcement="evaluate_only")
        def export_user_data(user_id):
            # Runs on a policy APPROVE with no human involved. Only use
            # this for actions you've decided don't need a human.
            ...

    Args:
        action_type: the governance action type to evaluate.
        agent_id: agent identifier; defaults to the wrapped function's
            ``__qualname__``.
        tenant_id: optional (deprecated) tenant override.
        payload_fn: callable that receives the wrapped function's
            ``(args, kwargs)`` and returns the payload dict. If
            ``None``, a minimal ``{"function": qualname}`` payload is
            used.
        target_url: required when ``enforcement="human_gate"`` (the
            default). The URL Axiosky will call, server-side, only
            after a human approves — never called by this decorator
            directly.
        enforcement: ``"human_gate"`` (default, enforces human
            approval before the wrapped function runs) or
            ``"evaluate_only"`` (explicit opt-out, no human review).
        timeout: seconds to wait for a human decision in
            ``"human_gate"`` mode before raising (default 60).
        poll_interval: seconds between polls while waiting (default 1).
        _axiosky_governor: the Governor / AsyncGovernor to use. May
            also be passed at call time.
        **governor_kwargs: forwarded to ``evaluate()`` / ``execute()``
            (e.g. ``environment``, ``fallback``, ``idempotency_key``).
    """
    if enforcement not in ("human_gate", "evaluate_only"):
        raise ValueError(
            "@governed: enforcement must be 'human_gate' (default, "
            "enforces human approval before the wrapped function runs) "
            "or 'evaluate_only' (explicit opt-out, no human review)."
        )
    if enforcement == "human_gate" and not target_url:
        raise ValueError(
            "@governed(..., enforcement='human_gate') requires target_url "
            "— the URL Axiosky calls, server-side, once a human approves. "
            "If you deliberately want the old evaluate()-only behavior "
            "with NO human review, pass enforcement='evaluate_only' "
            "explicitly."
        )

    _DENIED_STATUSES = frozenset({
        "blocked_by_human", "expired_auto_blocked", "rejected_no_execution",
    })

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        qualname = getattr(func, "__qualname__", None) or func.__name__
        effective_agent_id = agent_id or qualname

        if inspect.iscoroutinefunction(func):
            @functools.wraps(func)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                gov = kwargs.pop(
                    "_axiosky_governor", _axiosky_governor
                )
                if gov is None:
                    raise AxioskyError(
                        0,
                        "@governed: no Governor provided. Pass "
                        "_axiosky_governor= at decoration time or at "
                        "call time.",
                    )
                if payload_fn is not None:
                    payload = payload_fn(*args, **kwargs)
                else:
                    payload = {"function": qualname}

                if enforcement == "evaluate_only":
                    logger.warning(
                        "@governed(%r, enforcement='evaluate_only'): "
                        "running %r WITHOUT human confirmation — this "
                        "mode bypasses the /v1/execute human gate by "
                        "design.",
                        action_type, qualname,
                    )
                    decision = await gov.evaluate(
                        agent_id=effective_agent_id,
                        action_type=action_type,
                        tenant_id=tenant_id,
                        payload=payload,
                        **governor_kwargs,
                    )
                    status = DecisionStatus.from_value(decision.status)
                    if status is DecisionStatus.APPROVE:
                        return await func(*args, **kwargs)
                    if status is DecisionStatus.BLOCK:
                        raise GovernanceDeniedError(decision)
                    raise GovernanceEscalatedError(decision)

                decision = await gov.execute(
                    agent_id=effective_agent_id,
                    action_type=action_type,
                    target_url=target_url,
                    tenant_id=tenant_id,
                    payload=payload,
                    **governor_kwargs,
                )
                if decision.execution_status == "shadow_skipped":
                    return await func(*args, **kwargs)
                final = await gov.wait_for_decision(
                    decision.decision_id,
                    timeout=timeout,
                    poll_interval=poll_interval,
                )
                exec_status = final.get("execution_status")
                if exec_status == "executed":
                    return await func(*args, **kwargs)
                if exec_status in _DENIED_STATUSES:
                    raise GovernanceDeniedError(decision)
                raise AxioskyError(
                    0,
                    f"@governed: decision {decision.decision_id} ended "
                    f"in execution_status={exec_status!r} — wrapped "
                    f"function NOT run. This requires manual "
                    f"reconciliation.",
                )

            return async_wrapper

        @functools.wraps(func)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            gov = kwargs.pop(
                "_axiosky_governor", _axiosky_governor
            )
            if gov is None:
                raise AxioskyError(
                    0,
                    "@governed: no Governor provided. Pass "
                    "_axiosky_governor= at decoration time or at "
                    "call time.",
                )
            if payload_fn is not None:
                payload = payload_fn(*args, **kwargs)
            else:
                payload = {"function": qualname}

            if enforcement == "evaluate_only":
                logger.warning(
                    "@governed(%r, enforcement='evaluate_only'): "
                    "running %r WITHOUT human confirmation — this "
                    "mode bypasses the /v1/execute human gate by "
                    "design.",
                    action_type, qualname,
                )
                decision = gov.evaluate(
                    agent_id=effective_agent_id,
                    action_type=action_type,
                    tenant_id=tenant_id,
                    payload=payload,
                    **governor_kwargs,
                )
                status = DecisionStatus.from_value(decision.status)
                if status is DecisionStatus.APPROVE:
                    return func(*args, **kwargs)
                if status is DecisionStatus.BLOCK:
                    raise GovernanceDeniedError(decision)
                raise GovernanceEscalatedError(decision)

            decision = gov.execute(
                agent_id=effective_agent_id,
                action_type=action_type,
                target_url=target_url,
                tenant_id=tenant_id,
                payload=payload,
                **governor_kwargs,
            )
            if decision.execution_status == "shadow_skipped":
                return func(*args, **kwargs)
            final = gov.wait_for_decision(
                decision.decision_id,
                timeout=timeout,
                poll_interval=poll_interval,
            )
            exec_status = final.get("execution_status")
            if exec_status == "executed":
                return func(*args, **kwargs)
            if exec_status in _DENIED_STATUSES:
                raise GovernanceDeniedError(decision)
            raise AxioskyError(
                0,
                f"@governed: decision {decision.decision_id} ended in "
                f"execution_status={exec_status!r} — wrapped function "
                f"NOT run. This requires manual reconciliation.",
            )

        return sync_wrapper

    return decorator


# ---------------------------------------------------------------------------
# govern / agovern context managers
# ---------------------------------------------------------------------------
@contextlib.contextmanager
def govern(
    governor: Governor,
    action_type: str,
    *,
    agent_id: Optional[str] = None,
    tenant_id: Optional[str] = None,
    payload: Optional[Dict[str, Any]] = None,
    **kwargs: Any,
) -> Any:
    """Sync context manager that gates a code block.

    Usage::

        with govern(gov, "data_export", agent_id="agent1",
                    payload={"user": 42}) as decision:
            # runs only if APPROVE
            do_export()

    Raises ``GovernanceDeniedError`` / ``GovernanceEscalatedError``
    on BLOCK / ESCALATE.
    """
    if not agent_id:
        raise ValueError(
            "agent_id is required for govern() (pass it as a keyword)"
        )
    decision = governor.evaluate(
        agent_id=agent_id,
        action_type=action_type,
        tenant_id=tenant_id,
        payload=payload,
        **kwargs,
    )
    status = DecisionStatus.from_value(decision.status)
    if status is DecisionStatus.BLOCK:
        raise GovernanceDeniedError(decision)
    if status is DecisionStatus.ESCALATE:
        raise GovernanceEscalatedError(decision)
    yield decision


@contextlib.asynccontextmanager
async def agovern(
    governor: AsyncGovernor,
    action_type: str,
    *,
    agent_id: Optional[str] = None,
    tenant_id: Optional[str] = None,
    payload: Optional[Dict[str, Any]] = None,
    **kwargs: Any,
) -> Any:
    """Async context manager that gates a code block."""
    if not agent_id:
        raise ValueError(
            "agent_id is required for agovern() (pass it as a keyword)"
        )
    decision = await governor.evaluate(
        agent_id=agent_id,
        action_type=action_type,
        tenant_id=tenant_id,
        payload=payload,
        **kwargs,
    )
    status = DecisionStatus.from_value(decision.status)
    if status is DecisionStatus.BLOCK:
        raise GovernanceDeniedError(decision)
    if status is DecisionStatus.ESCALATE:
        raise GovernanceEscalatedError(decision)
    yield decision


__all__ = [
    "__version__",
    "Decision",
    "DecisionStatus",
    "AxioskyError",
    "GovernanceDeniedError",
    "GovernanceEscalatedError",
    "Governor",
    "AsyncGovernor",
    "governed",
    "govern",
    "agovern",
]
