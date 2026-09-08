"""Tests for the package's public API exports and version drift."""
import importlib
import re
from pathlib import Path

import axiosky


class TestPublicAPI:
    def test_version_is_string(self):
        assert isinstance(axiosky.__version__, str)
        assert re.match(r"^\d+\.\d+\.\d+", axiosky.__version__)

    def test_all_exports_present(self):
        expected = {
            "__version__",
            "Governor",
            "AsyncGovernor",
            "Decision",
            "DecisionStatus",
            "AxioskyError",
            "GovernanceDeniedError",
            "GovernanceEscalatedError",
            "governed",
            "govern",
            "agovern",
        }
        assert set(axiosky.__all__) == expected
        for name in expected:
            assert hasattr(axiosky, name), f"Missing export: {name}"

    def test_async_governor_exported(self):
        assert hasattr(axiosky, "AsyncGovernor")
        assert axiosky.AsyncGovernor is not None

    def test_decision_status_exported(self):
        assert hasattr(axiosky, "DecisionStatus")

    def test_governed_exported(self):
        assert callable(axiosky.governed)

    def test_govern_exported(self):
        assert callable(axiosky.govern)

    def test_agovern_exported(self):
        assert callable(axiosky.agovern)


class TestVersionDrift:
    def test_setup_reads_version_from_client(self):
        """setup.py must read __version__ from client.py (single source)."""
        setup_path = Path(axiosky.__file__).resolve().parent.parent / "setup.py"
        assert setup_path.exists(), f"setup.py not found at {setup_path}"
        src = setup_path.read_text()
        # Must NOT hardcode a version string in setup()
        assert 'version="0.' not in src, "setup.py hardcodes version"
        # Must read from client.py
        assert "client.py" in src
        assert "__version__" in src

    def test_init_version_matches_client(self):
        import axiosky.client as client_mod
        assert axiosky.__version__ == client_mod.__version__

    def test_pkg_info_version_matches(self):
        """The installed package metadata must match the runtime version."""
        pkg_info_path = (
            Path(axiosky.__file__).resolve().parent.parent
            / "axiosky.egg-info"
            / "PKG-INFO"
        )
        if pkg_info_path.exists():
            content = pkg_info_path.read_text()
            assert f"Version: {axiosky.__version__}" in content


class TestSyncContextManager:
    def test_sync_context_manager_closes(self):
        from tests.conftest import make_governor, approve_body

        gov = make_governor(lambda req: httpx.Response(200, json=approve_body()))
        with gov as g:
            assert g is gov
        assert gov._client.is_closed is True
