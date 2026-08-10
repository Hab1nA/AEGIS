"""Trusted, journaled connectors for role-facing external side effects.

Roles never reach the host network or working tree directly.  Every external
write is expressed as a plugin action, mediated by ``ToolBroker``, journaled
intent-first by the connector journal, and executed by a control-plane
connector that revalidates the untrusted arguments.
"""

from .checkpoint_plugin import CHECKPOINT_ACTION, build_checkpoint_plugin, checkpoint_generation
from .git_checkpoint import GitCheckpointConnector
from .journal import ConnectorJournalError, SqliteConnectorJournal

__all__ = [
    "CHECKPOINT_ACTION",
    "ConnectorJournalError",
    "GitCheckpointConnector",
    "SqliteConnectorJournal",
    "build_checkpoint_plugin",
    "checkpoint_generation",
]
