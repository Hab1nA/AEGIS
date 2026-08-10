"""Control-plane Git checkpoint connector for the plugin broker."""

from __future__ import annotations

import base64
import hashlib
from typing import Any, Mapping

from aegis.models import canonical_json
from aegis.plugins.abi import EffectClass, PluginManifest
from aegis.plugins.runtime import (
    ActionRequest,
    CapabilityGrant,
    ExternalEffectReceipt,
    ExternalIntent,
    PluginExecutionError,
)
from aegis.publishing.models import GitCheckpointRequest, GitFileChange
from aegis.publishing.publisher import GitPublisher

CHECKPOINT_ACTION = "aegis.git_checkpoint"
MAX_CHECKPOINT_CHANGES = 64
MAX_CHECKPOINT_MESSAGE = 512
MAX_CHECKPOINT_FILE_BYTES = 786_432


class GitCheckpointConnector:
    """Publish one role-owned checkpoint through the isolated Git publisher.

    The connector is control-plane code: it never imports or executes plugin
    code, and the Git remote/credentials stay in the publisher's environment.
    All request arguments are revalidated here before crossing to Git.
    """

    connector_id = "aegis-git-checkpoint"

    def __init__(self, publisher: GitPublisher) -> None:
        self.publisher = publisher

    def execute(
        self,
        manifest: PluginManifest,
        grant: CapabilityGrant,
        request: ActionRequest,
        intent: ExternalIntent,
    ) -> Mapping[str, Any]:
        if not isinstance(manifest, PluginManifest) or not isinstance(grant, CapabilityGrant):
            raise PluginExecutionError("checkpoint connector received invalid boundary objects")
        if not isinstance(request, ActionRequest) or request.action != CHECKPOINT_ACTION:
            raise PluginExecutionError("checkpoint connector received an unexpected action")
        spec = next(
            (item for item in manifest.actions if item.name == CHECKPOINT_ACTION),
            None,
        )
        if spec is None or spec.effect is not EffectClass.EXTERNAL:
            raise PluginExecutionError("checkpoint connector action is not declared external")
        checkpoint = self._checkpoint_from_arguments(grant, request)
        publication = self.publisher.publish_candidate(checkpoint)
        output = {
            "request_id": checkpoint.request_id,
            "new_commit": publication.receipt.new_commit,
            "ref": publication.receipt.ref,
        }
        output_digest = hashlib.sha256(canonical_json(output).encode("utf-8")).hexdigest()
        receipt = ExternalEffectReceipt.create(
            intent_id=intent.intent_id,
            request_id=intent.request_id,
            connector_id=self.connector_id,
            operation_id=intent.operation_id,
            output_sha256=output_digest,
            remote_receipt_sha256=hashlib.sha256(
                publication.receipt.new_commit.encode("ascii")
            ).hexdigest(),
        )
        return {
            "output": output,
            "elapsed_seconds": 0.0,
            "timed_out": False,
            "workspace_diff": None,
            "external_receipt": receipt.to_dict(),
        }

    def _checkpoint_from_arguments(
        self, grant: CapabilityGrant, request: ActionRequest
    ) -> GitCheckpointRequest:
        arguments = request.arguments
        if set(arguments) != {"base_commit", "message", "changes"}:
            raise PluginExecutionError("checkpoint arguments must be exactly base_commit, message, changes")
        base_commit = arguments["base_commit"]
        message = arguments["message"]
        changes = arguments["changes"]
        if not isinstance(base_commit, str) or len(base_commit) not in {40, 64}:
            raise PluginExecutionError("checkpoint base_commit must be a full Git commit id")
        if not isinstance(message, str) or not message.strip() or len(message) > MAX_CHECKPOINT_MESSAGE:
            raise PluginExecutionError("checkpoint message must be bounded non-empty text")
        if not isinstance(changes, tuple) or not changes or len(changes) > MAX_CHECKPOINT_CHANGES:
            raise PluginExecutionError("checkpoint changes must be a bounded non-empty array")
        converted: list[GitFileChange] = []
        paths: set[str] = set()
        for item in changes:
            if (
                not isinstance(item, Mapping)
                or set(item) != {"path", "delete", "content_base64", "executable"}
            ):
                raise PluginExecutionError("checkpoint change must contain exactly path, delete, content_base64, executable")
            path = item["path"]
            delete = item["delete"]
            encoded = item["content_base64"]
            executable = item["executable"]
            if not isinstance(path, str) or not path or "\\" in path or "\x00" in path or len(path) > 512:
                raise PluginExecutionError("checkpoint path must be a safe POSIX relative path")
            if not isinstance(delete, bool) or not isinstance(executable, bool):
                raise PluginExecutionError("checkpoint delete and executable must be booleans")
            if delete:
                if executable or encoded != "":
                    raise PluginExecutionError("checkpoint deletion must not carry content or executable mode")
                content: bytes | None = None
            else:
                if not isinstance(encoded, str) or len(encoded) > MAX_CHECKPOINT_FILE_BYTES * 4 // 3 + 16:
                    raise PluginExecutionError("checkpoint content_base64 is outside the size bound")
                try:
                    content = base64.b64decode(encoded, validate=True)
                except (ValueError, TypeError) as exc:
                    raise PluginExecutionError("checkpoint content_base64 is invalid") from exc
                if not content or len(content) > MAX_CHECKPOINT_FILE_BYTES:
                    raise PluginExecutionError("checkpoint file content is empty or oversized")
            if path in paths:
                raise PluginExecutionError("checkpoint paths must be unique")
            paths.add(path)
            converted.append(GitFileChange(path, content, executable))
        try:
            return GitCheckpointRequest.create(
                role=grant.role.value,
                generation_id=self._ref_component(grant.generation_id),
                base_commit=base_commit,
                changes=tuple(sorted(converted, key=lambda item: item.path)),
                message=message,
            )
        except (TypeError, ValueError) as exc:
            raise PluginExecutionError(f"checkpoint request is invalid: {exc}") from exc

    @staticmethod
    def _ref_component(generation_id: str) -> str:
        """Map a content address onto one safe Git ref component."""
        if not isinstance(generation_id, str) or not generation_id.startswith("sha256:"):
            raise PluginExecutionError("checkpoint generation id must be a sha256 content address")
        digest = generation_id.removeprefix("sha256:")
        if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
            raise PluginExecutionError("checkpoint generation id digest is invalid")
        return "gen-" + digest[:40]
