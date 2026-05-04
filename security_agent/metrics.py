"""
Prometheus metrics for Security Monitor.

Usage:
    from security_agent.metrics import MetricsExporter, get_metrics
    
    # In your code
    metrics = get_metrics()
    metrics.increment("security_events_total", {"severity": "HIGH"})
    metrics.record_latency("detection_latency_ms", 12.5)
    
    # Start HTTP server for Prometheus to scrape
    exporter = MetricsExporter(port=9090)
    exporter.start()
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Any

try:
    from prometheus_client import Counter, Gauge, Histogram, generate_latest

    HAS_PROMETHEUS = True
except ImportError:
    HAS_PROMETHEUS = False


@dataclass
class MetricsData:
    counters: dict[str, dict[str, int]] = field(default_factory=dict)
    gauges: dict[str, float] = field(default_factory=dict)
    histograms: dict[str, list[float]] = field(default_factory=dict)
    last_update: float = field(default_factory=time.time)
    _lock: threading.Lock = field(default_factory=threading.Lock)


class MetricsExporter:
    """
    Simple Prometheus-compatible metrics exporter.
    
    Provides /metrics endpoint for Prometheus scraping.
    """

    def __init__(self, port: int = 9090) -> None:
        self.port = port
        self._metrics = MetricsData()
        self._lock = threading.Lock()

    def start(self) -> None:
        """Start HTTP server in background thread."""
        if not HAS_PROMETHEUS:
            print("[metrics] prometheus_client not installed, metrics disabled")
            return
        
        import http.server
        import socketserver
        
        class MetricsHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/metrics":
                    self.send_response(200)
                    self.send_header("Content-Type", "text/plain; version=0.0.4")
                    self.end_headers()
                    metrics_output = get_prometheus_output()
                    self.wfile.write(metrics_output.encode())
                elif self.path == "/health":
                    self.send_response(200)
                    self.send_header("Content-Type", "text/plain")
                    self.end_headers()
                    self.wfile.write(b"OK")
                else:
                    self.send_response(404)
                    self.end_headers()
            
            def log_message(self, format, *args):
                pass  # Suppress logging
        
        def serve():
            with socketserver.TCPServer(("", self.port), MetricsHandler) as httpd:
                print(f"[metrics] Starting metrics server on port {self.port}")
                httpd.serve_forever()
        
        thread = threading.Thread(target=serve, daemon=True)
        thread.start()


_metrics_instance: MetricsData | None = None
_metrics_lock = threading.Lock()


def get_metrics() -> MetricsData:
    """Get or create the global metrics instance."""
    global _metrics_instance
    with _metrics_lock:
        if _metrics_instance is None:
            _metrics_instance = MetricsData()
        return _metrics_instance


def increment_counter(name: str, labels: dict[str, str] | None = None, value: int = 1) -> None:
    """Increment a counter metric."""
    if not HAS_PROMETHEUS:
        return
    
    metrics = get_metrics()
    with metrics._lock:
        if name not in metrics.counters:
            metrics.counters[name] = {}
        key = ",".join(f'{k}="{v}"' for k, v in (labels or {}).items()) or "default"
        metrics.counters[name][key] = metrics.counters[name].get(key, 0) + value


def set_gauge(name: str, value: float) -> None:
    """Set a gauge metric."""
    if not HAS_PROMETHEUS:
        return
    
    metrics = get_metrics()
    with metrics._lock:
        metrics.gauges[name] = value


def record_histogram(name: str, value: float) -> None:
    """Record a histogram value."""
    if not HAS_PROMETHEUS:
        return
    
    metrics = get_metrics()
    with metrics._lock:
        if name not in metrics.histograms:
            metrics.histograms[name] = []
        # Keep last 1000 values
        hist = metrics.histograms[name]
        hist.append(value)
        if len(hist) > 1000:
            hist.pop(0)


def get_prometheus_output() -> str:
    """Generate Prometheus-format output from collected metrics."""
    metrics = get_metrics()
    lines = []
    
    with metrics._lock:
        # Counters
        for name, values in metrics.counters.items():
            for labels, value in values.items():
                labels_str = "{" + labels + "}" if labels != "default" else ""
                lines.append(f"# TYPE {name} counter")
                lines.append(f"{name}{labels_str} {value}")
        
        # Gauges
        for name, value in metrics.gauges.items():
            lines.append(f"# TYPE {name} gauge")
            lines.append(f"{name} {value}")
        
        # Histograms (simplified - just basic stats)
        for name, values in metrics.histograms.items():
            if values:
                avg = sum(values) / len(values)
                min_val = min(values)
                max_val = max(values)
                lines.append(f"# TYPE {name} summary")
                lines.append(f"{name}_count {len(values)}")
                lines.append(f"{name}_sum {sum(values)}")
                lines.append(f"{name}_avg {avg:.2f}")
                lines.append(f"{name}_min {min_val:.2f}")
                lines.append(f"{name}_max {max_val:.2f}")
    
    return "\n".join(lines)


def instrument_detection(func):
    """Decorator to instrument detection functions."""
    def wrapper(*args, **kwargs):
        start = time.perf_counter()
        try:
            result = func(*args, **kwargs)
            latency_ms = (time.perf_counter() - start) * 1000
            record_histogram("detection_latency_ms", latency_ms)
            return result
        except Exception:
            increment_counter("detection_errors_total", {"function": func.__name__})
            raise
    return wrapper


class SecurityMonitorMetrics:
    """High-level metrics wrapper for SecurityMonitorApp."""
    
    def __init__(self) -> None:
        self._events_total = 0
        self._threats_detected = 0
        self._responses_executed = 0
        self._gateway_blocked = 0
    
    def record_event(self, event_type: str) -> None:
        self._events_total += 1
        increment_counter("security_events_total", {"type": event_type})
    
    def record_threat(self, severity: str) -> None:
        self._threats_detected += 1
        increment_counter("threats_detected_total", {"severity": severity})
    
    def record_response(self, action: str) -> None:
        self._responses_executed += 1
        increment_counter("responses_executed_total", {"action": action})
    
    def record_gateway_block(self, reason: str) -> None:
        self._gateway_blocked += 1
        increment_counter("gateway_blocks_total", {"reason": reason})
    
    def update_connection_status(self, connected: bool) -> None:
        set_gauge("monitor_connected", 1.0 if connected else 0.0)
    
    def update_queue_size(self, size: int) -> None:
        set_gauge("event_queue_size", float(size))


if __name__ == "__main__":
    # Quick test
    increment_counter("test_counter", {"label": "value"}, 5)
    set_gauge("test_gauge", 42.0)
    record_histogram("test_histogram", 12.5)
    record_histogram("test_histogram", 15.0)
    
    print(get_prometheus_output())