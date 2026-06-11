"""
Lab 11 — Monitoring & Alerts (Assignment Extra)

Tracks metrics from guardrail plugins and fires alerts
when thresholds are exceeded.
"""
from typing import Any


# Default alert thresholds
DEFAULT_THRESHOLDS = {
    "block_rate_max": 0.20,          # Alert if > 20% of requests blocked
    "rate_limit_hits_per_min": 5,    # Alert if > 5 rate-limit blocks per minute
    "judge_fail_rate_max": 0.30,     # Alert if > 30% of judge checks fail
    "latency_max_ms": 5000,          # Alert if avg latency > 5 seconds
}


class MonitoringAlert:
    """Tracks guardrail metrics and fires alerts when thresholds exceed.

    Collects stats from all plugins and checks against configurable thresholds.
    """

    def __init__(self, thresholds: dict[str, float] | None = None):
        self.thresholds = thresholds or DEFAULT_THRESHOLDS
        self.alerts: list[dict[str, Any]] = []
        self.plugins: list[Any] = []
        self._minute_samples: list[float] = []

    def register_plugin(self, plugin: Any):
        """Register a guardrail plugin to monitor."""
        self.plugins.append(plugin)

    def register_plugins(self, plugins: list[Any]):
        """Register multiple plugins at once."""
        self.plugins.extend(plugins)

    def _collect_metrics(self) -> dict[str, Any]:
        """Aggregate metrics from all registered plugins."""
        total_blocked = 0
        total_requests = 0
        total_rate_blocked = 0
        total_latency = 0.0
        latency_count = 0

        for plugin in self.plugins:
            name = getattr(plugin, "name", type(plugin).__name__).lower()

            # Each plugin may expose .stats property or .blocked_count / .total_count
            blocked = getattr(plugin, "blocked_count", 0)
            total = getattr(plugin, "total_count", 0)
            total_blocked += blocked
            total_requests += total

            if "rate" in name or "limiter" in name:
                total_rate_blocked += blocked

            # AuditLog stats include latency
            if hasattr(plugin, "stats"):
                stats = plugin.stats if callable(plugin.stats) else plugin.stats
                if isinstance(stats, dict):
                    if "avg_latency_ms" in stats:
                        total_latency += stats["avg_latency_ms"]
                        latency_count += 1

        block_rate = total_blocked / max(total_requests, 1)
        avg_latency = total_latency / max(latency_count, 1) if latency_count else 0.0

        return {
            "total_requests": total_requests,
            "total_blocked": total_blocked,
            "block_rate": block_rate,
            "rate_limit_hits": total_rate_blocked,
            "avg_latency_ms": round(avg_latency, 2),
        }

    def check_metrics(self) -> list[dict[str, Any]]:
        """Check all metrics against thresholds and fire alerts."""
        metrics = self._collect_metrics()
        new_alerts = []

        # Alert 1: Block rate too high
        if metrics["block_rate"] > self.thresholds["block_rate_max"]:
            alert = {
                "level": "WARNING",
                "metric": "block_rate",
                "value": metrics["block_rate"],
                "threshold": self.thresholds["block_rate_max"],
                "message": (
                    f"Block rate is {metrics['block_rate']:.0%} "
                    f"(threshold: {self.thresholds['block_rate_max']:.0%}). "
                    "May indicate false positives — review guardrail rules."
                ),
            }
            new_alerts.append(alert)

        # Alert 2: Rate limit hits too frequent
        if metrics["rate_limit_hits"] > self.thresholds["rate_limit_hits_per_min"]:
            alert = {
                "level": "INFO",
                "metric": "rate_limit_hits",
                "value": metrics["rate_limit_hits"],
                "threshold": self.thresholds["rate_limit_hits_per_min"],
                "message": (
                    f"Rate limit triggered {metrics['rate_limit_hits']} times — "
                    "possible abuse or too-aggressive rate limiting."
                ),
            }
            new_alerts.append(alert)

        # Alert 3: High latency
        if metrics["avg_latency_ms"] > self.thresholds["latency_max_ms"]:
            alert = {
                "level": "WARNING",
                "metric": "latency",
                "value": metrics["avg_latency_ms"],
                "threshold": self.thresholds["latency_max_ms"],
                "message": (
                    f"Average latency {metrics['avg_latency_ms']}ms exceeds threshold "
                    f"({self.thresholds['latency_max_ms']}ms). Consider optimizing."
                ),
            }
            new_alerts.append(alert)

        self.alerts.extend(new_alerts)

        if new_alerts:
            print(f"\n--- Monitoring: {len(new_alerts)} alert(s) ---")
            for alert in new_alerts:
                print(f"  [{alert['level']}] {alert['message']}")
        else:
            print("\n--- Monitoring: All metrics within thresholds ---")

        return new_alerts

    def print_summary(self):
        """Print a summary of all metrics."""
        metrics = self._collect_metrics()
        print("\n" + "=" * 60)
        print("MONITORING SUMMARY")
        print("=" * 60)
        print(f"Total requests:  {metrics['total_requests']}")
        print(f"Total blocked:   {metrics['total_blocked']} ({metrics['block_rate']:.0%})")
        print(f"Rate limit hits: {metrics['rate_limit_hits']}")
        print(f"Avg latency:     {metrics['avg_latency_ms']}ms")
        print(f"Active alerts:   {len(self.alerts)}")
        if self.alerts:
            for a in self.alerts[-3:]:
                print(f"  - [{a['level']}] {a['metric']}: {a['message'][:80]}...")
        print("=" * 60)
