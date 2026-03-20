from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field


class AiProviderKind(StrEnum):
    OPENAI_COMPATIBLE = "openai_compatible"
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    LOCAL = "local"


class AiCapability(StrEnum):
    CHAT = "chat"
    TOOL_CALLING = "tool_calling"
    JSON_OUTPUT = "json_output"
    EMBEDDINGS = "embeddings"


class AiProviderDescriptor(BaseModel):
    key: str
    kind: AiProviderKind
    display_name: str
    description: str
    capabilities: list[AiCapability]
    config_fields: list[str] = Field(default_factory=list)


class AiProviderCatalog(BaseModel):
    version: str
    providers: list[AiProviderDescriptor]
