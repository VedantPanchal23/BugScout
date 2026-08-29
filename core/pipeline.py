from __future__ import annotations

import os
import yaml
from typing import Optional

from core.mission_context import MissionContext, ScopeConfig
from core.scope_guard import ScopeGuard
from core.llm import LLMManager, LLMProvider
from core.loop import AgenticLoopController


class BugScoutPipeline:
    """
    High-level orchestrator for configuring and running the BugScout autonomous system.
    """

    def __init__(self, config_path: str = "config/scope.yaml", custom_llm: Optional[LLMProvider] = None, max_iterations: int = 2):
        self.config_path = config_path
        self.scope_config = self._load_scope_config(config_path)
        self.scope_guard = ScopeGuard(self.scope_config)
        self.llm = custom_llm or LLMManager.get_provider()
        self.context = MissionContext(
            target=self.scope_config.target,
            scope=self.scope_config,
            max_iterations=max_iterations
        )
        self.controller = AgenticLoopController(self.context, self.scope_guard, self.llm)

    def _load_scope_config(self, path: str) -> ScopeConfig:
        if not os.path.exists(path):
            raise FileNotFoundError(f"Mandatory scope configuration file not found at: {path}")

        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}

        return ScopeConfig(**data)

    async def run(self) -> MissionContext:
        """Run the full autonomous security assessment."""
        return await self.controller.execute_mission()
