"""The Gemini CLI extension installs this repository: it has to run this version, pass the API
key the way Gemini CLI allows, and its context file may only name tools the server has."""

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _extension() -> dict:
    return json.loads((ROOT / "gemini-extension.json").read_text(encoding="utf-8"))


def test_the_extension_runs_this_version_and_names_its_context_file():
    extension = _extension()
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    version = re.search(r'^version = "([^"]+)"', pyproject, re.MULTILINE).group(1)
    assert extension["version"] == version  # bump both with every release
    (server,) = extension["mcpServers"].values()
    assert server["args"] == [f"nodemaven-mcp=={version}"]
    assert (ROOT / extension["contextFileName"]).is_file()


def test_the_api_key_is_a_sensitive_setting_not_an_env_mapping():
    # Gemini CLI passes an extension only the variables its settings declare, and an `env`
    # mapping of a *KEY* variable expands to an empty string after its redaction.
    extension = _extension()
    (server,) = extension["mcpServers"].values()
    assert "env" not in server
    (setting,) = extension["settings"]
    assert setting["envVar"] == "NODEMAVEN_APIKEY" and setting["sensitive"] is True


def test_the_context_file_names_only_tools_the_server_has():
    context = (ROOT / "GEMINI.md").read_text(encoding="utf-8")
    source = (ROOT / "src" / "nodemaven_mcp" / "server.py").read_text(encoding="utf-8")
    tools = set(re.findall(r"@server\.tool\([^)]*\)\ndef (\w+)\(", source))
    # Every lowercase identifier in backticks; commands and env variables are not ones.
    named = {n for n in re.findall(r"`([a-z][a-z0-9_]*)`", context)}
    assert named <= tools, named - tools
