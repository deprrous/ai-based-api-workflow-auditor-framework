from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from api.app.database import session_scope
from api.app.db_models import ScanArtifactRecord
from api.repositories.artifact_repository import ArtifactRepository
from api.repositories.scan_repository import ScanRepository
from api.schemas.artifacts import (
    ApiSpecArtifactIngestRequest,
    ArtifactDetail,
    ArtifactKind,
    ArtifactMatchReference,
    ArtifactSummary,
    SourceArtifactIngestRequest,
)
from tools.analyzer.ingestion import (
    artifact_route_summaries,
    build_artifact_match_references,
    content_checksum,
    content_excerpt,
    parse_api_spec_artifact,
    parse_source_artifact,
    serialize_summary,
    summarize_artifact,
)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _to_detail(record: ScanArtifactRecord) -> ArtifactDetail:
    summary = summarize_artifact(
        artifact_id=record.id,
        scan_id=record.scan_id,
        kind=ArtifactKind(record.kind),
        name=record.name,
        path=record.path,
        language=record.language,
        format_name=record.format,
        content=record.content_text,
        parsed_summary=record.parsed_summary_json,
        created_at=record.created_at,
        updated_at=record.updated_at,
    )
    return ArtifactDetail(
        **summary.model_dump(),
        content_excerpt=record.content_excerpt,
        parsed_summary=record.parsed_summary_json,
    )


class ArtifactService:
    def ingest_source_artifact(self, scan_id: str, payload: SourceArtifactIngestRequest) -> ArtifactDetail | None:
        with session_scope() as session:
            if ScanRepository(session).get(scan_id) is None:
                return None

            now = _utc_now()
            parsed_summary = parse_source_artifact(payload.language, payload.content)
            record = ScanArtifactRecord(
                id=f"artifact-{uuid4().hex[:12]}",
                scan_id=scan_id,
                kind=ArtifactKind.SOURCE_CODE.value,
                name=payload.name,
                path=payload.path,
                language=payload.language,
                format=None,
                checksum=content_checksum(payload.content),
                content_text=payload.content,
                content_excerpt=content_excerpt(payload.content),
                parsed_summary_json=serialize_summary(parsed_summary),
                created_at=now,
                updated_at=now,
            )
            ArtifactRepository(session).add(record)
            session.flush()
            session.refresh(record)
            return _to_detail(record)

    def ingest_api_spec_artifact(self, scan_id: str, payload: ApiSpecArtifactIngestRequest) -> ArtifactDetail | None:
        with session_scope() as session:
            if ScanRepository(session).get(scan_id) is None:
                return None

            now = _utc_now()
            parsed_summary = parse_api_spec_artifact(payload.format, payload.content)
            record = ScanArtifactRecord(
                id=f"artifact-{uuid4().hex[:12]}",
                scan_id=scan_id,
                kind=ArtifactKind.API_SPEC.value,
                name=payload.name,
                path=payload.path,
                language=None,
                format=payload.format,
                checksum=content_checksum(payload.content),
                content_text=payload.content,
                content_excerpt=content_excerpt(payload.content),
                parsed_summary_json=serialize_summary(parsed_summary),
                created_at=now,
                updated_at=now,
            )
            ArtifactRepository(session).add(record)
            session.flush()
            session.refresh(record)
            return _to_detail(record)

    def list_artifacts(self, scan_id: str, *, kind: ArtifactKind | None = None) -> list[ArtifactSummary]:
        with session_scope() as session:
            records = ArtifactRepository(session).list_for_scan(scan_id, kind=kind.value if kind else None)
            return [
                summarize_artifact(
                    artifact_id=record.id,
                    scan_id=record.scan_id,
                    kind=ArtifactKind(record.kind),
                    name=record.name,
                    path=record.path,
                    language=record.language,
                    format_name=record.format,
                    content=record.content_text,
                    parsed_summary=record.parsed_summary_json,
                    created_at=record.created_at,
                    updated_at=record.updated_at,
                )
                for record in records
            ]

    def get_artifact(self, artifact_id: str) -> ArtifactDetail | None:
        with session_scope() as session:
            record = ArtifactRepository(session).get(artifact_id)
            return _to_detail(record) if record else None

    def match_artifacts(self, scan_id: str, *, method: str, path: str) -> list[ArtifactMatchReference]:
        with session_scope() as session:
            records = ArtifactRepository(session).list_for_scan(scan_id)
            references: list[ArtifactMatchReference] = []
            for record in records:
                references.extend(
                    build_artifact_match_references(
                        artifact_id=record.id,
                        artifact_name=record.name,
                        kind=ArtifactKind(record.kind),
                        parsed_summary=record.parsed_summary_json,
                        method=method,
                        path=path,
                    )
                )
            return references


artifact_service = ArtifactService()
