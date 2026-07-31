import httpx
import datetime as dt
from dataclasses import dataclass
from typing import Optional, Dict, Any

@dataclass
class Decision:
    decision_id: str
    status: str          # APPROVE | BLOCK | ESCALATE
    reason: str
    reason_code: str
    shadow_result: Optional[str] = None
    escalation_id: Optional[str] = None

    @property
    def approved(self) -> bool:
        return self.status == "APPROVE"

    @property
    def blocked(self) -> bool:
        return self.status == "BLOCK"

class AxioskyError(Exception):
    def __init__(self, status_code: int, detail: str):
        self.status_code = status_code
        self.detail = detail
        super().__init__(f"Axiosky API error {status_code}: {detail}")

class Governor:
    def __init__(self, api_key: str, base_url: str = "http://localhost:8000", timeout: float = 5.0):
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self._client = httpx.Client(
            base_url=self.base_url,
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=timeout,
        )

    def evaluate(
        self,
        agent_id: str,
        action_type: str,
        tenant_id: str,
        payload: Dict[str, Any],
        environment: str = "shadow",
        context_hooks: Optional[Dict[str, str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Decision:
        body = {
            "agent_id": agent_id,
            "action_type": action_type,
            "timestamp": dt.datetime.utcnow().isoformat() + "Z",
            "tenant_id": tenant_id,
            "environment": environment,
            "payload": payload,
        }
        if context_hooks: body["context_hooks"] = context_hooks
        if metadata: body["metadata"] = metadata

        resp = self._client.post("/v1/evaluate", json=body)
        if resp.status_code != 200:
            raise AxioskyError(resp.status_code, resp.text)

        data = resp.json()
        return Decision(
            decision_id=data["decision_id"],
            status=data["status"],
            reason=data["reason"],
            reason_code=data["reason_code"],
            shadow_result=data.get("shadow_result"),
            escalation_id=data.get("escalation_id"),
        )

    def close(self):
        self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()