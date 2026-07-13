"""DockerSandbox: real containment for untrusted code.

These prove the isolation properties that make the container tier safe: the network is
cut, the root filesystem is read-only, and only the tmpfs is writable. They need a
container engine, so they skip cleanly where none is installed (e.g. the dev box) and run
in CI, whose ubuntu runners ship docker.
"""
import pytest

from sabba.sandbox import Limits
from sabba.sandbox.docker import DockerSandbox, engine_available

pytestmark = pytest.mark.skipif(engine_available() is None,
                                reason="no container engine (docker/podman) on this host")


def _box():
    return DockerSandbox(image="alpine:3")


def test_container_runs_and_captures_output():
    r = _box().run(["sh", "-c", "echo hi-from-a-container"], limits=Limits(wall_seconds=60))
    assert r.exit_code == 0
    assert "hi-from-a-container" in r.stdout


def test_network_is_cut():
    # --network none leaves only loopback; there is no eth0 interface inside the container
    r = _box().run(["sh", "-c", "ls /sys/class/net"], limits=Limits(wall_seconds=60))
    assert r.exit_code == 0
    assert "lo" in r.stdout
    assert "eth0" not in r.stdout


def test_root_filesystem_is_read_only():
    r = _box().run(["sh", "-c", "echo x > /etc/should-fail"], limits=Limits(wall_seconds=60))
    assert r.exit_code != 0                       # read-only root rejects the write


def test_tmpfs_is_writable():
    r = _box().run(["sh", "-c", "echo ok > /tmp/t && cat /tmp/t"], limits=Limits(wall_seconds=60))
    assert r.exit_code == 0
    assert "ok" in r.stdout


def test_wall_clock_kill():
    r = _box().run(["sh", "-c", "sleep 30"], limits=Limits(wall_seconds=3))
    assert r.timed_out is True


def test_security_scan_isolated_catches_credential_read(tmp_path):
    # a hostile skill that reads a credential path is caught inside the container, and the
    # network is actually cut, so the read cannot be followed by exfiltration
    from sabba.security import scan_skill
    skill = tmp_path / "evil.py"
    skill.write_text('open("/root/.ssh/id_rsa").read()\n')
    r = scan_skill(str(skill), isolated=True)
    assert r["isolated"] is True
    assert r["risk"] == "dangerous"
    assert any(o["kind"] == "credential-read" for o in r["observations"])
