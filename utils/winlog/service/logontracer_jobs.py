"""Background job manager for LogonTracer analysis."""

from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass
from typing import Any

from utils.winlog.service.logontracer_service import build_logontracer_result, serialize_events

JOB_TTL_SEC = 20 * 60


@dataclass
class LogonTracerJob:
    job_id: str
    status: str
    progress: int
    message: str | None
    created_at: float
    updated_at: float
    expires_at: float
    result: dict[str, Any] | None
    error: str | None


class LogonTracerJobManager:
    def __init__(self) -> None:
        self._jobs: dict[str, LogonTracerJob] = {}
        self._lock = threading.Lock()

    def start_job(self, *, params: dict[str, Any], conn_str: str) -> str:
        self._cleanup()
        job_id = uuid.uuid4().hex
        now = time.time()
        job = LogonTracerJob(
            job_id=job_id,
            status="queued",
            progress=0,
            message="queued",
            created_at=now,
            updated_at=now,
            expires_at=now + JOB_TTL_SEC,
            result=None,
            error=None,
        )
        with self._lock:
            self._jobs[job_id] = job

        thread = threading.Thread(
            target=self._run_job,
            args=(job_id, params, conn_str),
            name=f"LogonTracerJob-{job_id}",
            daemon=True,
        )
        thread.start()
        return job_id

    def get_status(self, job_id: str) -> dict[str, Any] | None:
        self._cleanup()
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return None
            return {
                "job_id": job.job_id,
                "status": job.status,
                "progress": job.progress,
                "message": job.message,
                "error": job.error,
            }

    def get_graph(self, job_id: str) -> dict[str, Any] | None:
        job = self._get_done_job(job_id)
        if not job:
            return None
        return job.result.get("graph") if job.result else None

    def get_timeline(self, job_id: str) -> dict[str, Any] | None:
        job = self._get_done_job(job_id)
        if not job:
            return None
        return job.result.get("timeline") if job.result else None

    def get_sessions(
        self,
        *,
        job_id: str,
        start: int,
        length: int,
        search_value: str | None,
    ) -> dict[str, Any] | None:
        job = self._get_done_job(job_id)
        if not job or not job.result:
            return None
        sessions = job.result.get("sessions") or []
        total = len(sessions)
        filtered = self._filter_sessions(sessions, search_value)
        page = filtered[start : start + length] if length > 0 else filtered[start:]
        return {
            "recordsTotal": total,
            "recordsFiltered": len(filtered),
            "data": page,
        }

    def get_session_events(
        self,
        *,
        job_id: str,
        host_ip: str,
        session_id: str,
        start_time: str | None,
        end_time: str | None,
    ) -> list[dict[str, Any]] | None:
        job = self._get_done_job(job_id)
        if not job or not job.result:
            return None
        events = job.result.get("events") or []
        result = []
        for event in events:
            entities = event.get("entities") or {}
            if str(event.get("host_ip") or "") != host_ip:
                continue
            if str(entities.get("session_id") or "") != session_id:
                continue
            ts = str(event.get("timestamp") or "")
            if start_time and ts < start_time:
                continue
            if end_time and ts > end_time:
                continue
            result.append(event)
        return serialize_events(result)

    def _filter_sessions(self, sessions: list[dict[str, Any]], search_value: str | None) -> list[dict[str, Any]]:
        if not search_value:
            return sessions
        needle = search_value.strip().lower()
        if not needle:
            return sessions
        output = []
        for session in sessions:
            haystack = " ".join(
                [
                    str(session.get("host_ip") or ""),
                    str(session.get("session_id") or ""),
                    str(session.get("user") or ""),
                    str(session.get("src_ip") or ""),
                    str(session.get("status") or ""),
                    str(session.get("start_time") or ""),
                    str(session.get("end_time") or ""),
                ]
            ).lower()
            if needle in haystack:
                output.append(session)
        return output

    def _get_done_job(self, job_id: str) -> LogonTracerJob | None:
        self._cleanup()
        with self._lock:
            job = self._jobs.get(job_id)
            if not job or job.status != "done":
                return None
            return job

    def _run_job(self, job_id: str, params: dict[str, Any], conn_str: str) -> None:
        def progress_cb(progress: int, message: str) -> None:
            self._update_job(job_id, progress=progress, message=message)

        self._update_job(job_id, status="running", progress=1, message="starting")
        try:
            result = build_logontracer_result(
                conn_str=conn_str,
                start=params.get("start"),
                end=params.get("end"),
                user=params.get("user"),
                src_ip=params.get("src_ip"),
                host_names=params.get("host_names"),
                bucket=params.get("bucket"),
                progress_cb=progress_cb,
            )
            serialized = {
                "graph": result.graph,
                "timeline": result.timeline,
                "sessions": result.sessions,
                "events": result.events,
                "bucket": result.bucket,
            }
            self._update_job(job_id, status="done", progress=100, message="done", result=serialized)
        except Exception as exc:
            self._update_job(job_id, status="error", progress=100, message=str(exc), error=str(exc))

    def _update_job(self, job_id: str, **updates: Any) -> None:
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return
            for key, value in updates.items():
                if hasattr(job, key):
                    setattr(job, key, value)
            job.updated_at = time.time()
            job.expires_at = job.updated_at + JOB_TTL_SEC

    def _cleanup(self) -> None:
        now = time.time()
        with self._lock:
            expired = [job_id for job_id, job in self._jobs.items() if job.expires_at <= now]
            for job_id in expired:
                self._jobs.pop(job_id, None)


LOGONTRACER_JOBS = LogonTracerJobManager()
