from setuptools import setup, find_packages

setup(
    name="axiosky",
    version="0.1.0",
    description="Python SDK for Axiosky AI Governance Control Plane",
    packages=find_packages(),
    install_requires=[
        "httpx>=0.24.0"
    ],
    python_requires=">=3.8",
)