"""Setup for the Axiosky Python SDK.

The version is read from ``axiosky/client.py`` (single source of truth)
to prevent version drift between the package metadata and the runtime
module (audit §4).
"""
import re
from pathlib import Path

from setuptools import find_packages, setup

_here = Path(__file__).resolve().parent
_init_src = (_here / "axiosky" / "client.py").read_text(encoding="utf-8")
_match = re.search(
    r"^__version__\s*=\s*['\"]([^'\"]+)['\"]", _init_src, re.MULTILINE
)
if not _match:
    raise RuntimeError("Could not find __version__ in axiosky/client.py")
VERSION = _match.group(1)

setup(
    name="axiosky",
    version=VERSION,
    description="Python SDK for Axiosky AI Governance Control Plane",
    packages=find_packages(include=["axiosky", "axiosky.*"]),
    install_requires=[
        "httpx>=0.24.0",
    ],
    python_requires=">=3.8",
)
