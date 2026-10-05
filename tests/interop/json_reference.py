"""Independent Python JSON oracle over side-effect-free MCP ping requests."""
import argparse
import json
import random
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument("--ipg", required=True)
args = parser.parse_args()
rng = random.Random(9580)
ids = [0, -1, -(2**63), 2**64-1, 2**53-1, 2**53, 2**53+1,
       "", "\0\n\r\t", 'quote " slash \\', "😀", "é", "安全"]
ids += [rng.randrange(-(2**63), 2**64) for _ in range(500)]
lines = [json.dumps({"jsonrpc":"2.0", "id":"init", "method":"initialize",
                    "params":{"protocolVersion":"2025-11-25", "capabilities":{},
                              "clientInfo":{"name":"json-oracle", "version":"1"}}}),
         json.dumps({"jsonrpc":"2.0", "method":"notifications/initialized"})]
for index, value in enumerate(ids):
    lines.append(json.dumps({"jsonrpc":"2.0", "id":value, "method":"ping"},
                            ensure_ascii=bool(index % 2)))
bad_ids = ["1.0", "1e0", "-0", "18446744073709551616", "-9223372036854775809"]
for value in bad_ids:
    lines.append('{"jsonrpc":"2.0","id":'+value+',"method":"ping"}')
bad_json = [
    r'{"jsonrpc":"2.0","id":1,"\u0069d":2,"method":"ping"}',
    r'{"jsonrpc":"2.0","id":"\ud800","method":"ping"}',
    r'{"jsonrpc":"2.0","id":"\ud800\u0000","method":"ping"}',
    r'{"jsonrpc":"2.0","id":"\udc00","method":"ping"}',
    '{"jsonrpc":"2.0","id":01,"method":"ping"}',
    '{"jsonrpc":"2.0","id":1e9999,"method":"ping"}',
]
lines.extend(bad_json)
lines.append('{"jsonrpc":"2.0","id":"after-errors","method":"ping"}')
result = subprocess.run([args.ipg,"mcp"], input=("\n".join(lines)+"\n").encode(),
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
assert result.returncode == 0, result.stderr.decode(errors="replace")
responses = [json.loads(line) for line in result.stdout.splitlines()]
assert len(responses) == len(lines)-1
assert responses[0]["id"] == "init" and "result" in responses[0]
for response, expected in zip(responses[1:], ids):
    assert response == {"jsonrpc":"2.0", "id":expected, "result":{}}, response
    assert type(response["id"]) is type(expected)
for response in responses[1+len(ids):-1]:
    assert "error" in response and response["id"] is None, response
assert responses[-1] == {"jsonrpc":"2.0", "id":"after-errors", "result":{}}
print(json.dumps({"ok":True,"exact_id_checks":len(ids),
                  "rejected_ambiguous_or_invalid_inputs":len(bad_ids)+len(bad_json)}))
