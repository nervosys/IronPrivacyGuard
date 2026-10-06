"""Official MCP Python SDK against `ipg mcp-http` (Streamable HTTP, JSON responses).

Starts the server on an ephemeral loopback port with a bearer token, connects
with the SDK's streamable HTTP client, lists and validates tools, runs
successful and failing tool calls, and checks that a wrong token is refused.
"""
import argparse
import asyncio
import json
import os
from pathlib import Path
import subprocess
import tempfile

import httpx2
from jsonschema import Draft202012Validator
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamable_http_client


async def exercise(url, token, directory):
    headers = {"Authorization": f"Bearer {token}"}
    async with httpx2.AsyncClient(headers=headers, timeout=30) as http:
        async with streamable_http_client(url, http_client=http) as streams:
            read, write = streams[0], streams[1]
            async with ClientSession(read, write) as session:
                await session.initialize()
                tools = (await session.list_tools()).tools
                assert len(tools) == 71
                for tool in tools:
                    Draft202012Validator.check_schema(tool.input_schema)
                document = Path(directory) / "document"
                document.write_bytes(b"MCP over loopback HTTP")
                result = await session.call_tool("ipg_hash", {"input": str(document)})
                assert not result.is_error and result.structured_content["ok"] is True
                missing = await session.call_tool("ipg_hash", {"input": str(Path(directory) / "missing")})
                assert missing.is_error and missing.structured_content["error"]["code"] == "io_error"
                return len(tools)


async def refused(url):
    async with httpx2.AsyncClient(headers={"Authorization": "Bearer wrong"}, timeout=30) as http:
        response = await http.post(url, content=b"{}", headers={"Content-Type": "application/json",
                                                                  "Accept": "application/json"})
        assert response.status_code == 401, response.status_code


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ipg", type=Path, required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="ipg-mcp-http-") as directory:
        token = os.urandom(32).hex()
        token_file = Path(directory) / "token"
        token_file.write_text(token)
        process = subprocess.Popen([str(args.ipg.resolve()), "mcp-http", "--listen", "127.0.0.1:0",
                                    "--token-file", str(token_file)], stderr=subprocess.PIPE, text=True)
        try:
            announced = json.loads(process.stderr.readline())
            url = f"http://{announced['listening']}{announced['endpoint']}"
            tools = asyncio.run(exercise(url, token, directory))
            asyncio.run(refused(url))
        finally:
            process.kill()
            process.wait()
    print(json.dumps({"ok": True, "transport": "streamable-http", "tools": tools}))


if __name__ == "__main__":
    main()
