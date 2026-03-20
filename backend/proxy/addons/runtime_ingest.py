# pyright: reportMissingImports=false

from __future__ import annotations

from types import SimpleNamespace
from typing import TYPE_CHECKING, Any

try:
    from mitmproxy import ctx
    from mitmproxy import http
except ModuleNotFoundError:  # pragma: no cover - import guard for local unit tests
    ctx = SimpleNamespace(options=SimpleNamespace(), log=SimpleNamespace(warn=lambda _: None))
    http = SimpleNamespace(HTTPFlow=Any)

if TYPE_CHECKING:  # pragma: no cover
    from mitmproxy.http import HTTPFlow

from proxy.capture.runtime_ingest import RuntimeIngestEmitter, RuntimeIngestOptions, split_csv


class RuntimeIngestAddon:
    def __init__(self) -> None:
        self._emitter: RuntimeIngestEmitter | None = None

    def load(self, loader) -> None:
        loader.add_option("auditor_backend_url", str, "http://127.0.0.1:8000/api/v1", "Backend base URL for runtime ingest.")
        loader.add_option("auditor_scan_id", str, "", "Scan identifier that should receive observed target traffic.")
        loader.add_option("auditor_ingest_token", str, "", "Worker ingest token sent to the backend API.")
        loader.add_option("auditor_include_hosts", str, "", "Optional comma-separated host allowlist for captured target traffic.")
        loader.add_option("auditor_include_path_prefixes", str, "/", "Comma-separated path prefixes that should be treated as API traffic.")
        loader.add_option("auditor_ignore_methods", str, "OPTIONS,CONNECT", "Comma-separated HTTP methods ignored by the addon.")
        loader.add_option("auditor_timeout_seconds", float, 3.0, "Backend ingest timeout in seconds.")

    def running(self) -> None:
        self._refresh_emitter()

    def configure(self, updates) -> None:
        if any(option.startswith("auditor_") for option in updates):
            self._refresh_emitter()

    def response(self, flow: Any) -> None:
        if self._emitter is None:
            return

        if not self._emitter.options.scan_id or not self._emitter.options.ingest_token:
            ctx.log.warn("runtime ingest addon is enabled but auditor_scan_id or auditor_ingest_token is missing")
            return

        self._emitter.process_flow(flow)

    def _refresh_emitter(self) -> None:
        options = RuntimeIngestOptions(
            backend_url=ctx.options.auditor_backend_url,
            scan_id=ctx.options.auditor_scan_id,
            ingest_token=ctx.options.auditor_ingest_token,
            include_hosts=split_csv(ctx.options.auditor_include_hosts),
            include_path_prefixes=split_csv(ctx.options.auditor_include_path_prefixes) or ("/",),
            ignore_methods=tuple(method.upper() for method in split_csv(ctx.options.auditor_ignore_methods)),
            timeout_seconds=float(ctx.options.auditor_timeout_seconds),
        )
        self._emitter = RuntimeIngestEmitter(options=options, logger=ctx.log.warn)


addons = [RuntimeIngestAddon()]
