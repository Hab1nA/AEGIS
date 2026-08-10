from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from aegis.sandbox.bootstrap import (
    BootstrapSpec,
    apply_plan,
    installation_plan,
    render_files,
    validate_rendered,
)

IMAGE = "example.invalid/aegis@sha256:" + "b" * 64


class BootstrapTests(unittest.TestCase):
    def test_plan_contains_required_hardening_and_is_dry_run(self) -> None:
        spec = BootstrapSpec(image=IMAGE)
        plan = installation_plan(spec)
        self.assertEqual(plan["mode"], "dry-run")
        modes = {item["path"]: item["mode"] for item in plan["files"]}
        rendered = render_files(spec)
        self.assertIn("enabled=false", rendered["/etc/wsl.conf"])
        self.assertIn("appendWindowsPath=false", rendered["/etc/wsl.conf"])
        self.assertIn('netns = "private"', rendered["/etc/containers/containers.conf"])
        config = json.loads(rendered["/etc/aegis-sandbox/agent.json"])
        self.assertEqual(config["image"], IMAGE)
        self.assertEqual(config["max_workspace_bytes"], 67_108_864)
        self.assertIn("loop,nosuid,nodev", rendered["/usr/local/libexec/aegis-workspace-setup"])
        self.assertIn("statvfs", rendered["/usr/local/libexec/aegis-workspace-setup"])
        self.assertEqual(modes["/usr/local/libexec/aegis-workspace-setup"], "0755")
        self.assertNotIn("/etc/aegis-sandbox/workspace-quota.policy", rendered)

    def test_validation_rejects_unpinned_image_and_weakened_policy(self) -> None:
        with self.assertRaisesRegex(ValueError, "pinned"):
            render_files(BootstrapSpec(image="python:latest"))
        spec = BootstrapSpec(image=IMAGE)
        files = render_files(spec)
        files["/etc/wsl.conf"] = files["/etc/wsl.conf"].replace(
            "appendWindowsPath=false", "appendWindowsPath=true"
        )
        with self.assertRaisesRegex(ValueError, "appendWindowsPath"):
            validate_rendered(files, spec)

    def test_apply_is_explicit_non_overwriting_staging_write(self) -> None:
        spec = BootstrapSpec(image=IMAGE)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            written = apply_plan(spec, root)
            self.assertEqual(len(written), len(render_files(spec)))
            self.assertTrue((root / "etc" / "wsl.conf").is_file())
            with self.assertRaises(FileExistsError):
                apply_plan(spec, root)

    def test_apply_rejects_filesystem_root(self) -> None:
        with self.assertRaisesRegex(ValueError, "non-root"):
            apply_plan(BootstrapSpec(image=IMAGE), Path(Path.cwd().anchor))

    def test_helper_grants_traverse_on_sandbox_root(self) -> None:
        """IMAGE.parent (e.g. /var/lib/aegis-sandbox) must be 0o711 so the
        unprivileged aegis user can traverse to the workspace without being
        able to list directory contents or read the backing image."""
        spec = BootstrapSpec(image=IMAGE)
        helper = render_files(spec)["/usr/local/libexec/aegis-workspace-setup"]
        self.assertIn("IMAGE.parent.mkdir(mode=0o711", helper)
        self.assertIn("os.chown(IMAGE.parent, 0, 0); os.chmod(IMAGE.parent, 0o711)", helper)

    def test_helper_quota_marker_world_readable(self) -> None:
        """The quota marker must be 0o644 so the unprivileged agent can read
        it; only root should write it (via atomic tmp+replace)."""
        spec = BootstrapSpec(image=IMAGE)
        helper = render_files(spec)["/usr/local/libexec/aegis-workspace-setup"]
        self.assertIn("os.chmod(tmp, 0o644)", helper)

    def test_helper_backing_image_stays_root_only(self) -> None:
        """The backing ext4 image must be created 0o600 root:root."""
        spec = BootstrapSpec(image=IMAGE)
        helper = render_files(spec)["/usr/local/libexec/aegis-workspace-setup"]
        self.assertIn("os.O_CREAT|os.O_EXCL|os.O_WRONLY, 0o600", helper)

    def test_helper_workspace_owned_by_sandbox_user(self) -> None:
        """The mounted workspace must be chowned to the sandbox user at 0o700."""
        spec = BootstrapSpec(image=IMAGE)
        helper = render_files(spec)["/usr/local/libexec/aegis-workspace-setup"]
        self.assertIn("os.chown(ROOT, uid, gid); os.chmod(ROOT, 0o700)", helper)

    def test_validation_rejects_missing_traverse_permission(self) -> None:
        """validate_rendered must fail if the helper omits the 0o711 traverse mode."""
        spec = BootstrapSpec(image=IMAGE)
        files = render_files(spec)
        helper = files["/usr/local/libexec/aegis-workspace-setup"]
        files["/usr/local/libexec/aegis-workspace-setup"] = helper.replace(
            "os.chown(IMAGE.parent, 0, 0); os.chmod(IMAGE.parent, 0o711)",
            "os.chown(IMAGE.parent, 0, 0); os.chmod(IMAGE.parent, 0o700)",
        )
        with self.assertRaisesRegex(ValueError, "0o711"):
            validate_rendered(files, spec)

    def test_validation_rejects_missing_readable_marker(self) -> None:
        """validate_rendered must fail if the helper uses restrictive marker perms."""
        spec = BootstrapSpec(image=IMAGE)
        files = render_files(spec)
        helper = files["/usr/local/libexec/aegis-workspace-setup"]
        files["/usr/local/libexec/aegis-workspace-setup"] = helper.replace("0o644", "0o600")
        with self.assertRaisesRegex(ValueError, "0o644"):
            validate_rendered(files, spec)


if __name__ == "__main__":
    unittest.main()
