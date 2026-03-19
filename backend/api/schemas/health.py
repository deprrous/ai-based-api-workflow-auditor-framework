from __future__ import annotations

from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    status: str = Field(description="Current service health state.", examples=["ok"])
    service: str = Field(description="Service name shown to API consumers.")
    environment: str = Field(description="Current deployment environment.")
    version: str = Field(description="Current application version.")
