from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from api.schemas.verifier_jobs import BrowserVisitSpec


class BrowserExecutor(Protocol):
    def visit(self, visit: BrowserVisitSpec, *, base_url: str, headers: dict[str, str]) -> str: ...


@dataclass(frozen=True, slots=True)
class PlaywrightBrowserExecutor:
    headless: bool = True
    timeout_seconds: float = 10.0
    browser_name: str = "chromium"

    def visit(self, visit: BrowserVisitSpec, *, base_url: str, headers: dict[str, str]) -> str:
        try:
            from playwright.sync_api import sync_playwright
        except ModuleNotFoundError as exc:  # pragma: no cover
            raise RuntimeError("Playwright is not installed for browser execution.") from exc

        if not base_url:
            raise RuntimeError("A browser base URL is required for headless browser verification.")

        target_url = f"{base_url.rstrip('/')}{visit.path}"
        with sync_playwright() as playwright:
            launcher = getattr(playwright, self.browser_name)
            browser = launcher.launch(headless=self.headless)
            context = browser.new_context(extra_http_headers=headers)
            page = context.new_page()
            page.goto(target_url, wait_until="networkidle", timeout=int(self.timeout_seconds * 1000))
            page.wait_for_timeout(visit.wait_seconds * 1000)
            browser.close()
        return target_url
