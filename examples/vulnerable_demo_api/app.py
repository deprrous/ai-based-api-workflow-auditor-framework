from __future__ import annotations

import asyncio
from itertools import count
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse

app = FastAPI(title="Vulnerable Demo API", version="0.1.0")

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
    return {"projects": [{"id": 123, "name": "Demo Project"}]}


@app.post("/v1/projects/{project_id}/members")
async def invite_member(project_id: int, payload: dict[str, Any], request: Request) -> dict[str, Any]:
    return {
        "project_id": project_id,
        "invited": payload,
        "actor": actor_from_request(request),
    }


@app.get("/v1/search")
async def search(q: str = "") -> PlainTextResponse:
    unsafe_query = f"SELECT * FROM products WHERE name LIKE '%{q}%'"  # intentional vulnerable demo sink
    if "pg_sleep" in q.lower():
        await asyncio.sleep(3)
        return PlainTextResponse(f"Query delayed: {unsafe_query}", status_code=200)
    if any(token in q.lower() for token in ("'", "union", "--", "or 1=1")):
        return PlainTextResponse("SQL syntax error near 'UNION'", status_code=500)
    return PlainTextResponse(f"Executed query: {unsafe_query}", status_code=200)


@app.post("/v1/imports")
async def create_import(payload: dict[str, Any]) -> JSONResponse:
    target_url = str(payload.get("url") or payload.get("callback_url") or "")
    if not target_url:
        raise HTTPException(status_code=400, detail="url or callback_url is required")

    if target_url.startswith("http://169.254.169.254/latest/meta-data/"):
        return JSONResponse(
            {
                "fetched": target_url,
                "metadata": "instance-id: i-demo123 ami-id: ami-demo123",
            }
        )

    if target_url.startswith("http://127.0.0.1") or target_url.startswith("http://localhost"):
        return JSONResponse(
            {
                "fetched": target_url,
                "result": "localhost connection succeeded against internal service",
            }
        )

    async with httpx.AsyncClient(follow_redirects=True, timeout=5.0) as client:
        response = await client.get(target_url)
        return JSONResponse(
            {
                "fetched": target_url,
                "status": response.status_code,
                "body_excerpt": response.text[:200],
            }
        )


@app.get("/v1/preview", response_class=HTMLResponse)
async def preview(html: str = "") -> HTMLResponse:
    return HTMLResponse(f"<html><body><h1>Preview</h1><div>{html}</div></body></html>")


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
