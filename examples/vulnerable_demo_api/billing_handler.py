from fastapi import APIRouter, Request

router = APIRouter()

project_billing = {
    123: {"project_id": 123, "tenant": "tenant-alpha", "amount": 2400, "owner": "project-owner"},
    999999: {"project_id": 999999, "tenant": "tenant-beta", "amount": 4800, "owner": "tenant-beta-owner"},
}


@router.get("/v1/projects/{project_id}/billing")
async def get_project_billing(project_id: int, request: Request) -> dict:
    # Intentional BOLA/IDOR demo flaw: returns any project's billing data without ownership checks.
    return {
        "actor": request.headers.get("Authorization", "anonymous"),
        "billing": project_billing.get(project_id, {"project_id": project_id, "tenant": "unknown-tenant"}),
    }
