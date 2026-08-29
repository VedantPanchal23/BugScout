from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import Optional, Any
from core.mission_context import MissionContext
from core.scope_guard import ScopeGuard
from core.llm import LLMProvider


class BaseAgent(ABC):
    """Base class for all BugScout autonomous security agents."""

    def __init__(
        self,
        name: str,
        context: MissionContext,
        scope_guard: ScopeGuard,
        llm: LLMProvider,
    ):
        self.name = name
        self.context = context
        self.scope_guard = scope_guard
        self.llm = llm
        self.logger = logging.getLogger(f"BugScout.{name}")

    def log(self, message: str, level: str = "INFO") -> None:
        """Log an event to the mission context and console."""
        self.context.log_event(self.name, message, level)
        if level == "ERROR":
            self.logger.error(message)
        elif level == "WARNING":
            self.logger.warning(message)
        else:
            self.logger.info(message)

    @abstractmethod
    async def run(self) -> None:
        """Execute the agent's core responsibility."""
        pass
