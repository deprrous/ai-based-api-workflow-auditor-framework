from __future__ import annotations

from itertools import count
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse

from examples.vulnerable_demo_api.billing_handler import router as billing_router
from examples.vulnerable_demo_api.imports_handler import router as imports_router
from examples.vulnerable_demo_api.preview_handler import router as preview_router
from examples.vulnerable_demo_api.project_admin_handler import router as project_admin_router
from examples.vulnerable_demo_api.project_members_handler import router as project_members_router
from examples.vulnerable_demo_api.search_handler import router as search_router

app = FastAPI(title="Vulnerable Demo API", version="0.1.0")

app.include_router(search_router)
app.include_router(imports_router)
app.include_router(preview_router)
app.include_router(project_members_router)
app.include_router(project_admin_router)
app.include_router(billing_router)

comment_ids = count(1)
comments: dict[int, dict[str, Any]] = {}


def actor_from_request(request: Request) -> str:
    authorization = request.headers.get("Authorization", "")
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() == "bearer" and token:
        return token.strip()
    return "anonymous"


@app.get("/v1/projects")
async def list_projects() -> dict[str, Any]:
    return {
        "projects": [
            {"id": 123, "name": "Tenant Alpha Project"},
            {"id": 999999, "name": "Tenant Beta Project"},
        ]
    }


@app.post("/v1/comments")
async def create_comment(payload: dict[str, Any], request: Request) -> dict[str, Any]:
    content = str(payload.get("content") or payload.get("message") or "")
    comment_id = next(comment_ids)
    comments[comment_id] = {
        "id": comment_id,
        "content": content,
        "actor": actor_from_request(request),
    }
    return {"id": comment_id, "stored": True}


@app.get("/v1/comments/{comment_id}/render", response_class=HTMLResponse)
async def render_comment(comment_id: int) -> HTMLResponse:
    comment = comments.get(comment_id)
    if comment is None:
        raise HTTPException(status_code=404, detail="Comment not found")
    return HTMLResponse(f"<html><body><article>{comment['content']}</article></body></html>")
