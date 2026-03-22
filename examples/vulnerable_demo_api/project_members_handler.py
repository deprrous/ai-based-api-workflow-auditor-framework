from fastapi import APIRouter, Request

router = APIRouter()


@router.post("/v1/projects/{project_id}/members")
async def invite_member(project_id: int, payload: dict, request: Request) -> dict:
    return {
        "project_id": project_id,
        "invited": payload,
        "actor": request.headers.get("Authorization", "anonymous"),
    }
