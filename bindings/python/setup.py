#!/usr/bin/env python3
"""
Setup script for Security Envelopes PolicyEngine Python bindings
"""

from setuptools import setup, find_packages
from pyo3_build_config import BuildConfig
import os


# Read the README file
def read_readme():
    readme_path = os.path.join(os.path.dirname(__file__), "README.md")
    if os.path.exists(readme_path):
        with open(readme_path, "r", encoding="utf-8") as f:
            return f.read()
    return ""


# Read version from Cargo.toml
def get_version():
    cargo_path = os.path.join(os.path.dirname(__file__), "Cargo.toml")
    if os.path.exists(cargo_path):
        with open(cargo_path, "r", encoding="utf-8") as f:
            for line in f:
                if line.startswith("version ="):
                    return line.split("=")[1].strip().strip('"')
    return "0.1.0"


setup(
    name="policyengine",
    version=get_version(),
    description="Python bindings for Security Envelopes PolicyEngine",
    long_description=read_readme(),
    long_description_content_type="text/markdown",
    author="Security Envelopes Team",
    author_email="team@security-envelopes.org",
    url="https://github.com/security-envelopes/security-envelopes",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    python_requires=">=3.9",
    install_requires=[
        "pydantic>=2.0.0",
        "typing-extensions>=4.0.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-asyncio>=0.21.0",
            "pytest-cov>=4.0.0",
            "black>=23.0.0",
            "flake8>=6.0.0",
            "mypy>=1.0.0",
            "isort>=5.12.0",
        ],
        "yaml": [
            "pyyaml>=6.0.0",
        ],
        "async": [
            "asyncio>=3.4.3",
        ],
    },
    include_package_data=True,
    zip_safe=False,
    build_config=BuildConfig(
        cargo_manifest_path="Cargo.toml",
        target_dir="target",
        features=["pyo3/extension-module"],
    ),
)
