"""The Gemini CLI extension installs this repository: it has to name this version, and its
context file may only name tools the server has."""

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_the_extension_names_this_version_and_its_context_file():
    extension = json.loads((ROOT / "gemini-extension.json").read_text(encoding="utf-8"))
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    version = re.search(r'^version = "([^"]+)"', pyproject, re.MULTILINE).group(1)
    assert extension["version"] == version  # bump it with every release
    (server,) = extension["mcpServers"].values()
    assert server["args"] == ["nodemaven-mcp"]
    assert (ROOT / extension["contextFileName"]).is_file()


def test_the_context_file_names_only_tools_the_server_has():
    context = (ROOT / "GEMINI.md").read_text(encoding="utf-8")
    source = (ROOT / "src" / "nodemaven_mcp" / "server.py").read_text(encoding="utf-8")
    tools = set(re.findall(r"@server\.tool\([^)]*\)\ndef (\w+)\(", source))
    named = set(re.findall(r"`([a-z_]+)`", context)) - {"proxy_url_"}
    named = {n for n in named if "_" in n and not n.isupper()}
    assert named <= tools, named - tools
