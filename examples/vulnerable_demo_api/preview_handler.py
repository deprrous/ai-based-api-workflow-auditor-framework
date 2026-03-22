from fastapi import APIRouter
from fastapi.responses import HTMLResponse

router = APIRouter()


@router.get("/v1/preview", response_class=HTMLResponse)
async def preview(html: str = "") -> HTMLResponse:
    return HTMLResponse(f"<html><body><h1>Preview</h1><div>{html}</div></body></html>")
