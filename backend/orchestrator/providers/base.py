from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from api.schemas.ai import AiCapability, AiProviderDescriptor, AiProviderKind


@dataclass(frozen=True, slots=True)
class ProviderSettingsField:
    name: str


class AiProvider(Protocol):
    descriptor: AiProviderDescriptor

    def validate(self) -> None: ...


def build_descriptor(
    *,
    key: str,
    kind: AiProviderKind,
    display_name: str,
    description: str,
    capabilities: list[AiCapability],
    config_fields: list[str],
) -> AiProviderDescriptor:
    return AiProviderDescriptor(
        key=key,
        kind=kind,
        display_name=display_name,
        description=description,
        capabilities=capabilities,
        config_fields=config_fields,
    )
