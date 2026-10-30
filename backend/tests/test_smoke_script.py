"""
Tests for Roadshow Smoke Self-Check Script (scripts/smoke.py).
Ensures 10-second pre-roadshow reliability check passes all criteria:
1. Python environment and required dependency packages
2. Writable data directories
3. ChromaDB regulation knowledge base status
4. DashScope API / Offline Emergency fallback status
5. PaddleOCR / Heuristic OCR engine status
6. Source code security scan (zero plaintext API keys)
"""

import os
import re
import sys
import subprocess
from pathlib import Path
import pytest


def test_smoke_module_importable():
    """Verify that smoke script can be imported and exposes core checking functions."""
    repo_root = Path(__file__).resolve().parent.parent.parent
    scripts_dir = repo_root / "scripts"
    if str(scripts_dir) not in sys.path:
        sys.path.insert(0, str(scripts_dir))

    import smoke  # noqa: F401
    assert hasattr(smoke, "run_all_checks")
    assert hasattr(smoke, "check_python_environment")
    assert hasattr(smoke, "check_writable_directories")
    assert hasattr(smoke, "check_rag_knowledge_base")
    assert hasattr(smoke, "check_model_services")
    assert hasattr(smoke, "check_source_security_keys")


def test_smoke_individual_checks():
    """Verify each individual check passes in the project environment."""
    repo_root = Path(__file__).resolve().parent.parent.parent
    scripts_dir = repo_root / "scripts"
    if str(scripts_dir) not in sys.path:
        sys.path.insert(0, str(scripts_dir))

    import smoke

    env_ok, env_msg = smoke.check_python_environment()
    assert env_ok is True, f"Python environment check failed: {env_msg}"

    dir_ok, dir_msg = smoke.check_writable_directories()
    assert dir_ok is True, f"Writable directories check failed: {dir_msg}"

    rag_ok, rag_msg = smoke.check_rag_knowledge_base()
    assert rag_ok is True, f"RAG knowledge base check failed: {rag_msg}"

    model_ok, model_msg = smoke.check_model_services()
    assert model_ok is True, f"Model services check failed: {model_msg}"

    sec_ok, sec_msg = smoke.check_source_security_keys(repo_root)
    assert sec_ok is True, f"Security key check failed: {sec_msg}"


def test_smoke_script_execution_cli():
    """Execute python scripts/smoke.py in a subprocess and verify exit code 0 and output format."""
    repo_root = Path(__file__).resolve().parent.parent.parent
    smoke_script = repo_root / "scripts" / "smoke.py"
    
    result = subprocess.run(
        [sys.executable, str(smoke_script)],
        cwd=str(repo_root),
        capture_output=True,
        text=True,
        timeout=15,
        env={**os.environ, "PYTHONPATH": f"{repo_root / 'backend'}:{repo_root}"}
    )

    assert result.returncode == 0, f"smoke.py failed with stderr: {result.stderr}"
    assert "出海易审 (CrossBorder SafeGuard)" in result.stdout
    assert "[PASS]" in result.stdout or "✓" in result.stdout or "OK" in result.stdout
    assert "自检通过" in result.stdout or "ALL CHECKS PASSED" in result.stdout


def test_source_security_scan_catches_leak(tmp_path):
    """Verify security scanner detects rogue API keys if accidentally introduced."""
    repo_root = Path(__file__).resolve().parent.parent.parent
    scripts_dir = repo_root / "scripts"
    if str(scripts_dir) not in sys.path:
        sys.path.insert(0, str(scripts_dir))

    import smoke

    # Create a temp directory with a file containing a leaked key
    fake_code_file = tmp_path / "bad_file.py"
    fake_code_file.write_text('API_KEY = "sk-abcdef12345678901234567890"', encoding="utf-8")

    sec_ok, sec_msg = smoke.check_source_security_keys(tmp_path)
    assert sec_ok is False
    assert "sk-" in sec_msg or "泄露" in sec_msg or "leak" in sec_msg.lower()
