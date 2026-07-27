from __future__ import annotations

from pathlib import Path

from ..config import RuntimeConfig
from ..pipeline.runtime import LocalPipelineResult
from ..pipeline.runtime import run_local_pipeline


class RuntimeService:
    def run_local(
        self,
        *,
        cfg: RuntimeConfig,
        sensor_id: str,
        labels_path: Path | None = None,
        report_out: Path | None = None,
        visual_out: Path | None = None,
    ) -> LocalPipelineResult:
        return run_local_pipeline(
            cfg=cfg,
            sensor_id=sensor_id,
            labels_path=labels_path,
            report_out=report_out,
            visual_out=visual_out,
        )
