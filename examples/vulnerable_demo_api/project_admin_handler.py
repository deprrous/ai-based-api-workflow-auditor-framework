from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse

router = APIRouter()


@router.delete("/v1/projects/{project_id}")
async def delete_project(project_id: int, request: Request):
    actor = request.headers.get("Authorization", "anonymous")
    if actor == "anonymous":
        raise HTTPException(status_code=401, detail="Authentication required")
    # Intentional BFLA demo flaw: any authenticated actor can delete a project.
    return JSONResponse(status_code=200, content={"deleted": True, "project_id": project_id, "actor": actor})
