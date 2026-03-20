from __future__ import annotations

from fastapi import APIRouter

from api.schemas.producer_contracts import ProducerContractCatalog
from api.services.producer_contract_service import producer_contract_service

router = APIRouter(prefix="/contracts", tags=["contracts"])


@router.get("/runtime-ingest", response_model=ProducerContractCatalog, summary="Read supported runtime ingest producer contracts")
async def get_runtime_ingest_contracts() -> ProducerContractCatalog:
    return producer_contract_service.get_catalog()
