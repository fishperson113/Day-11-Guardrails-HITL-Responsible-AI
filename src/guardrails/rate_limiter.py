"""
Lab 11 — Rate Limiter Plugin (Assignment Extra)

Sliding-window rate limiter per user.
Blocks requests that exceed the max allowed in a time window.
"""
import time
from collections import defaultdict, deque

from google.genai import types
from google.adk.plugins import base_plugin
from google.adk.agents.invocation_context import InvocationContext


class RateLimitPlugin(base_plugin.BasePlugin):
    """Rate limiter using a sliding window per user.

    Tracks request timestamps per user_id and blocks requests
    if the count in the current window exceeds max_requests.
    """

    def __init__(self, max_requests: int = 10, window_seconds: int = 60):
        super().__init__(name="rate_limiter")
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        # user_id -> deque of timestamps
        self.user_windows: dict[str, deque] = defaultdict(deque)
        self.blocked_count = 0
        self.total_count = 0

    def _block_response(self, message: str) -> types.Content:
        """Create a Content object with a block message."""
        return types.Content(
            role="model",
            parts=[types.Part.from_text(text=message)],
        )

    async def on_user_message_callback(
        self,
        *,
        invocation_context: InvocationContext,
        user_message: types.Content,
    ) -> types.Content | None:
        """Check rate limit before allowing message through."""
        self.total_count += 1

        user_id = invocation_context.user_id if invocation_context else "anonymous"
        now = time.time()
        window = self.user_windows[user_id]

        # Remove expired timestamps (older than window_seconds)
        while window and window[0] < now - self.window_seconds:
            window.popleft()

        # Check if over limit
        if len(window) >= self.max_requests:
            self.blocked_count += 1
            oldest = window[0] if window else now
            wait_time = int((oldest + self.window_seconds) - now)
            return self._block_response(
                f"Rate limit exceeded. You have sent {self.max_requests} requests "
                f"in {self.window_seconds} seconds. Please wait {wait_time} seconds "
                "before sending another request."
            )

        # Allow — add current timestamp
        window.append(now)
        return None

    @property
    def stats(self) -> dict:
        """Return current rate limit stats."""
        return {
            "blocked": self.blocked_count,
            "total": self.total_count,
            "block_rate": self.blocked_count / max(self.total_count, 1),
        }
