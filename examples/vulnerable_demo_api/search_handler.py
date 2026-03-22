from fastapi import APIRouter
from fastapi.responses import PlainTextResponse
import asyncio

router = APIRouter()


@router.get("/v1/search")
async def search(q: str = "") -> PlainTextResponse:
    unsafe_query = f"SELECT * FROM products WHERE name LIKE '%{q}%'"
    if "pg_sleep" in q.lower():
        await asyncio.sleep(3)
        return PlainTextResponse(f"Query delayed: {unsafe_query}", status_code=200)
    if any(token in q.lower() for token in ("'", "union", "--", "or 1=1")):
        return PlainTextResponse("SQL syntax error near 'UNION'", status_code=500)
    return PlainTextResponse(f"Executed query: {unsafe_query}", status_code=200)
