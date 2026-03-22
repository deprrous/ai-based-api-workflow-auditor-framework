from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse
import httpx

router = APIRouter()


@router.post("/v1/imports")
async def create_import(payload: dict) -> JSONResponse:
    target_url = str(payload.get("url") or payload.get("callback_url") or "")
    if not target_url:
        raise HTTPException(status_code=400, detail="url or callback_url is required")

    if target_url.startswith("http://169.254.169.254/latest/meta-data/"):
        return JSONResponse({"fetched": target_url, "metadata": "instance-id: i-demo123 ami-id: ami-demo123"})

    if target_url.startswith("http://127.0.0.1") or target_url.startswith("http://localhost"):
        return JSONResponse({"fetched": target_url, "result": "localhost connection succeeded against internal service"})

    async with httpx.AsyncClient(follow_redirects=True, timeout=5.0) as client:
        response = await client.get(target_url)
        return JSONResponse({"fetched": target_url, "status": response.status_code, "body_excerpt": response.text[:200]})
