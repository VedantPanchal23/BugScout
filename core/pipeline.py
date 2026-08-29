from __future__ import annotations

import os
import yaml
from urllib.parse import urlparse
from typing import Optional

from core.mission_context import MissionContext, ScopeConfig
from core.scope_guard import ScopeGuard
from core.llm import LLMManager, LLMProvider
from core.auth_manager import AuthManager
from core.loop import AgenticLoopController


class BugScoutPipeline:
    """
    High-level orchestrator for configuring and running the BugScout autonomous platform.
    Supports dynamic target injection (any arbitrary URL), atomic state checkpointing, and scan resuming.
    """

    def __init__(
        self,
        config_path: str = "config/scope.yaml",
        target_override: Optional[str] = None,
        custom_llm: Optional[LLMProvider] = None,
        max_iterations: int = 2,
        resume: bool = False,
        checkpoint_path: Optional[str] = None
    ):
        self.config_path = config_path
        if os.path.exists(config_path):
            self.scope_config = self._load_scope_config(config_path)
        else:
            self.scope_config = ScopeConfig(target=target_override or "http://127.0.0.1:8888")

        # Dynamically configure target if provided
        if target_override:
            clean_target = target_override.strip()
            if not clean_target.startswith("http://") and not clean_target.startswith("https://"):
                clean_target = "http://" + clean_target

            self.scope_config.target = clean_target
            parsed_target = urlparse(clean_target)
            hostname = parsed_target.hostname or clean_target

            # Auto-populate allowed hosts for the target
            if hostname not in self.scope_config.allowed_hosts:
                self.scope_config.allowed_hosts.append(hostname)

            wildcard_host = f"*.{hostname}"
            if wildcard_host not in self.scope_config.allowed_hosts:
                self.scope_config.allowed_hosts.append(wildcard_host)

            # Auto-enable local/LAN scanning if targeting localhost, 127.0.0.1, or private intranet subnets
            if hostname in ["127.0.0.1", "localhost", "0.0.0.0"] or hostname.startswith("192.168.") or hostname.startswith("10.") or hostname.startswith("172."):
                self.scope_config.allow_localhost_for_testing = True

            # Ensure open crawl path scope for live target
            self.scope_config.allowed_paths = ["/*"]

        self.checkpoint_file = checkpoint_path or self.scope_config.checkpoint_path

        # Resume context from checkpoint if requested and exists
        if resume and os.path.exists(self.checkpoint_file):
            self.context = MissionContext.load_checkpoint(self.checkpoint_file)
            self.context.scope = self.scope_config
        else:
            self.context = MissionContext(
                target=self.scope_config.target,
                scope=self.scope_config,
                max_iterations=max_iterations
            )

        self.scope_guard = ScopeGuard(self.scope_config)
        self.llm = custom_llm or LLMManager.get_provider()
        self.auth_manager = AuthManager(self.scope_config.auth)
        self.controller = AgenticLoopController(self.context, self.scope_guard, self.llm, self.auth_manager)

    def _load_scope_config(self, path: str) -> ScopeConfig:
        if not os.path.exists(path):
            raise FileNotFoundError(f"Mandatory scope configuration file not found at: {path}")

        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}

        return ScopeConfig(**data)

    async def run(self) -> MissionContext:
        """Run the full autonomous security assessment."""
        return await self.controller.execute_mission()
