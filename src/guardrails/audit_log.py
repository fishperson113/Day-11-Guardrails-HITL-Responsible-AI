"""
Lab 11 — Audit Log Plugin (Assignment Extra)

Records every interaction (input, output, block events, latency).
Exports to JSON for analysis and compliance.
"""
import json
import time as time_module
from datetime import datetime, timezone
from typing import Any

from google.genai import types
from google.adk.plugins import base_plugin
from google.adk.agents.invocation_context import InvocationContext


class AuditLogPlugin(base_plugin.BasePlugin):
    """Records every interaction for compliance and debugging.

    Captures:
    - User input and agent output
    - Which layer (if any) blocked the request
    - Latency per request
    - Timestamp and user_id

    Never blocks — only observes.
    """

    def __init__(self):
        super().__init__(name="audit_log")
        self.logs: list[dict[str, Any]] = []
        self._current_entry: dict[str, Any] | None = None
        self._start_time: float | None = None

    def _extract_text(self, content) -> str:
        """Extract plain text from a Content object or similar."""
        text = ""
        if hasattr(content, "content") and content.content:
            return self._extract_text(content.content)
        if hasattr(content, "parts") and content.parts:
            for part in content.parts:
                if hasattr(part, "text") and part.text:
                    text += part.text
        return text

    async def on_user_message_callback(
        self,
        *,
        invocation_context: InvocationContext,
        user_message: types.Content,
    ) -> types.Content | None:
        """Record the incoming message. Never blocks."""
        user_id = invocation_context.user_id if invocation_context else "anonymous"
        self._current_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "user_id": user_id,
            "input": self._extract_text(user_message),
            "blocked_by": None,
            "output": None,
            "latency_ms": None,
        }
        self._start_time = time_module.time()
        return None  # never block

    async def after_model_callback(self, *, callback_context, llm_response):
        """Record the response and calculate latency."""
        if self._current_entry and self._start_time:
            elapsed = (time_module.time() - self._start_time) * 1000
            self._current_entry["latency_ms"] = round(elapsed, 2)
            self._current_entry["output"] = self._extract_text(llm_response)
            self.logs.append(self._current_entry)

        self._current_entry = None
        self._start_time = None
        return llm_response

    def record_blocked(self, layer_name: str, user_input: str, response_text: str,
                       latency_ms: float | None = None, user_id: str = "unknown"):
        """Manually record an interaction that was blocked by a layer."""
        self.logs.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "user_id": user_id,
            "input": user_input,
            "output": response_text,
            "blocked_by": layer_name,
            "latency_ms": round(latency_ms, 2) if latency_ms else None,
        })

    def export_json(self, filepath: str = "audit_log.json"):
        """Export all logs to a JSON file."""
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(self.logs, f, indent=2, ensure_ascii=False)
        print(f"Audit log exported to {filepath} ({len(self.logs)} entries)")

    @property
    def stats(self) -> dict:
        """Return summary stats from the audit log."""
        total = len(self.logs)
        blocked = sum(1 for entry in self.logs if entry.get("blocked_by"))
        latencies = [
            entry.get("latency_ms", 0) or 0
            for entry in self.logs
            if entry.get("latency_ms")
        ]
        avg_latency = sum(latencies) / len(latencies) if latencies else 0.0
        return {
            "total_requests": total,
            "blocked": blocked,
            "block_rate": blocked / max(total, 1),
            "avg_latency_ms": round(avg_latency, 2),
        }
