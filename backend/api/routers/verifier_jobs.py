from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status

from api.app.security import require_verifier_job_token
from api.schemas.verifier_jobs import (
    ClaimVerifierJobRequest,
    ClaimVerifierJobResponse,
    CompleteVerifierJobRequest,
    FailVerifierJobRequest,
    VerifierJobDetail,
)
from api.services.verifier_job_service import verifier_job_service

router = APIRouter(prefix="/verifier-jobs", tags=["verifier-jobs"])


@router.get("/{verifier_job_id}", response_model=VerifierJobDetail, summary="Read verifier job detail")
async def get_verifier_job(verifier_job_id: str) -> VerifierJobDetail:
    verifier_job = verifier_job_service.get_verifier_job(verifier_job_id)
    if verifier_job is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Verifier job not found.")

    return verifier_job


@router.post("/claim", response_model=ClaimVerifierJobResponse, summary="Claim the next queued verifier job")
async def claim_verifier_job(
    payload: ClaimVerifierJobRequest,
    _: None = Depends(require_verifier_job_token),
) -> ClaimVerifierJobResponse:
    job = verifier_job_service.claim_verifier_job(payload)
    return ClaimVerifierJobResponse(job=job)


@router.post("/{verifier_job_id}/complete", response_model=VerifierJobDetail, summary="Mark a verifier job as completed")
async def complete_verifier_job(
    verifier_job_id: str,
    payload: CompleteVerifierJobRequest,
    _: None = Depends(require_verifier_job_token),
) -> VerifierJobDetail:
    job = verifier_job_service.complete_verifier_job(verifier_job_id, payload)
    if job is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Verifier job not found.")

    return job


@router.post("/{verifier_job_id}/fail", response_model=VerifierJobDetail, summary="Fail or retry a verifier job")
async def fail_verifier_job(
    verifier_job_id: str,
    payload: FailVerifierJobRequest,
    _: None = Depends(require_verifier_job_token),
) -> VerifierJobDetail:
    job = verifier_job_service.fail_verifier_job(verifier_job_id, payload)
    if job is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Verifier job not found.")

    return job
