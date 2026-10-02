"""Exercise IPG's AWS KMS provider against a local emulator with AWS semantics.

The emulator implements GetPublicKey, Sign (ECDSA_SHA_384 over a DIGEST, and
ML_DSA_SHAKE_256 over a RAW message or an EXTERNAL_MU representative, for ML_DSA_65
keys) and DeriveSharedSecret (ECDH returning the raw shared secret, as AWS documents). It
verifies every request's SigV4 signature with botocore, AWS's own signer, and
rejects requests whose signature, credentials or key usage are wrong.

LocalStack is not used: its DeriveSharedSecret applies HKDF to the ECDH result,
which real AWS KMS does not. All keys and credentials here are PUBLIC TEST DATA.
"""
import argparse
import base64
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, mldsa
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed, decode_dss_signature, encode_dss_signature

ACCESS_KEY, SECRET_KEY = "AKIAIPGTESTEXAMPLE01", "ipg/test/secret/key/for/local/emulator/only"
REGION, ACCOUNT = "us-gov-west-1", "123456789012"
# Temporary credentials issued by the IMDS and container emulators: key -> (secret, token).
TEMPORARY = {
    "ASIAIPGIMDSEXAMPLE01": ("ipg/test/imds/secret", "ipg-imds-session-token"),
    "ASIAIPGECSEXAMPLE001": ("ipg/test/container/secret", "ipg-container-session-token"),
    "ASIAIPGSTSEXAMPLE001": ("ipg/test/sts+secret&/x", "ipg-web-identity-session-token"),
    "ASIAIPGSSOEXAMPLE001": ("ipg/test/sso/secret", "ipg-sso-session-token"),
}
SSO_TOKEN, SSO_START_URL = "ipg-sso-bearer-token", "https://ipg-test.awsapps.com/start"
ROLE_ARN = f"arn:aws-us-gov:iam::{ACCOUNT}:role/ipg-signer"
WEB_IDENTITY_TOKEN = "eyJhbGciOiJSUzI1NiJ9.ipg-test-oidc-token.signature"
IMDS_TOKEN, ROLE, CONTAINER_TOKEN = "ipg-imds-v2-token", "ipg-test-role", "ipg-container-authorization"


class Emulator:
    def __init__(self):
        self.keys = {}
        self.calls = []

    def create(self, usage, spec="ECC_NIST_P384"):
        arn = f"arn:aws-us-gov:kms:{REGION}:{ACCOUNT}:key/{uuid.uuid4()}"
        key = mldsa.MLDSA65PrivateKey.generate() if spec == "ML_DSA_65" else ec.generate_private_key(ec.SECP384R1())
        self.keys[arn] = {"usage": usage, "spec": spec, "key": key}
        return arn

    def public_der(self, arn):
        return self.keys[arn]["key"].public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)

    def handle(self, target, body):
        self.calls.append(target)
        key = self.keys.get(body.get("KeyId"))
        if key is None:
            return 400, {"__type": "NotFoundException", "message": "Key not found"}
        if target == "GetPublicKey":
            return 200, {"KeyId": body["KeyId"], "KeySpec": key["spec"], "KeyUsage": key["usage"],
                         "PublicKey": base64.b64encode(self.public_der(body["KeyId"])).decode()}
        if target == "Sign" and key["spec"] == "ML_DSA_65":
            # RAW messages are signed with an empty context; EXTERNAL_MU is the 64-byte
            # FIPS 204 representative, which may carry any context.
            message, kind = base64.b64decode(body["Message"]), body.get("MessageType")
            if body.get("SigningAlgorithm") != "ML_DSA_SHAKE_256" or kind not in ("RAW", "EXTERNAL_MU") \
                    or (kind == "RAW" and len(message) > 4096) or (kind == "EXTERNAL_MU" and len(message) != 64):
                return 400, {"__type": "ValidationException", "message": "Invalid ML-DSA signing request"}
            self.calls.append(f"Sign/{kind}")
            signature = key["key"].sign(message) if kind == "RAW" else key["key"].sign_mu(message)
            return 200, {"KeyId": body["KeyId"], "Signature": base64.b64encode(signature).decode(),
                         "SigningAlgorithm": "ML_DSA_SHAKE_256"}
        if target == "Sign":
            if key["usage"] != "SIGN_VERIFY" or body.get("SigningAlgorithm") != "ECDSA_SHA_384" \
                    or body.get("MessageType") != "DIGEST":
                return 400, {"__type": "InvalidKeyUsageException", "message": "Invalid signing request"}
            digest = base64.b64decode(body["Message"])
            assert len(digest) == 48
            signature = key["key"].sign(digest, ec.ECDSA(Prehashed(hashes.SHA384())))
            return 200, {"KeyId": body["KeyId"], "Signature": base64.b64encode(signature).decode(),
                         "SigningAlgorithm": "ECDSA_SHA_384"}
        if target == "DeriveSharedSecret":
            if key["usage"] != "KEY_AGREEMENT" or body.get("KeyAgreementAlgorithm") != "ECDH":
                return 400, {"__type": "InvalidKeyUsageException", "message": "Invalid agreement request"}
            peer = serialization.load_der_public_key(base64.b64decode(body["PublicKey"]))
            shared = key["key"].exchange(ec.ECDH(), peer)
            return 200, {"KeyId": body["KeyId"], "SharedSecret": base64.b64encode(shared).decode(),
                         "KeyAgreementAlgorithm": "ECDH", "KeyOrigin": "AWS_KMS"}
        return 400, {"__type": "UnsupportedOperationException", "message": target}


def serve(emulator):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            body = self.rfile.read(int(self.headers["content-length"]))
            status, payload = self.authorize(body)
            if status == 200:
                status, payload = emulator.handle(self.headers["x-amz-target"].split(".", 1)[1], json.loads(body))
            data = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("content-type", "application/x-amz-json-1.1")
            self.send_header("content-length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def authorize(self, body):
            authorization = self.headers.get("authorization", "")
            access_key = authorization.split("Credential=")[-1].split("/")[0]
            known = {ACCESS_KEY: (SECRET_KEY, None), **TEMPORARY}
            if access_key not in known:
                return 400, {"__type": "UnrecognizedClientException", "message": "Unknown access key"}
            secret, token = known[access_key]
            if token is not None and self.headers.get("x-amz-security-token") != token:
                return 400, {"__type": "UnrecognizedClientException", "message": "Bad session token"}
            signed = authorization.split("SignedHeaders=")[1].split(",")[0].split(";")
            # Re-sign the received request with botocore and require an identical header.
            request = AWSRequest(method="POST", url=f"http://{self.headers['host']}/", data=body,
                                 headers={name: self.headers[name] for name in signed})
            signer = SigV4Auth(Credentials(access_key, secret, self.headers.get("x-amz-security-token")),
                               "kms", REGION)
            request.context["timestamp"] = self.headers["x-amz-date"]  # the client's signing time
            canonical = signer.canonical_request(request)
            expected = signer.signature(signer.string_to_sign(request, canonical), request)
            if authorization.rsplit("Signature=", 1)[-1] != expected:
                return 400, {"__type": "InvalidSignatureException", "message": "Signature mismatch"}
            return 200, None

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def serve_credentials():
    """IMDSv2 and container-credential endpoints issuing the TEMPORARY keys."""
    def document(key):
        secret, token = TEMPORARY[key]
        return {"Code": "Success", "AccessKeyId": key, "SecretAccessKey": secret, "Token": token,
                "Expiration": "2099-01-01T00:00:00Z"}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def reply(self, status, body):
            data = body if isinstance(body, bytes) else json.dumps(body).encode()
            self.send_response(status)
            self.send_header("content-length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_POST(self):
            # STS AssumeRoleWithWebIdentity: an unsigned form-encoded call.
            from urllib.parse import parse_qs
            query = parse_qs(self.rfile.read(int(self.headers["content-length"])).decode())
            single = {k: v[0] for k, v in query.items()}
            if single.get("Action") != "AssumeRoleWithWebIdentity" or single.get("RoleArn") != ROLE_ARN \
                    or single.get("WebIdentityToken") != WEB_IDENTITY_TOKEN:
                return self.reply(400, b"<ErrorResponse><Error><Code>InvalidIdentityToken</Code></Error></ErrorResponse>")
            secret, token = TEMPORARY["ASIAIPGSTSEXAMPLE001"]
            xml = ("<AssumeRoleWithWebIdentityResponse><AssumeRoleWithWebIdentityResult><Credentials>"
                   f"<AccessKeyId>ASIAIPGSTSEXAMPLE001</AccessKeyId><SecretAccessKey>{secret.replace('&', '&amp;')}</SecretAccessKey>"
                   f"<SessionToken>{token}</SessionToken><Expiration>2099-01-01T00:00:00Z</Expiration>"
                   "</Credentials></AssumeRoleWithWebIdentityResult></AssumeRoleWithWebIdentityResponse>")
            self.reply(200, xml.encode())

        def do_PUT(self):
            if self.path == "/latest/api/token" and self.headers.get("x-aws-ec2-metadata-token-ttl-seconds"):
                return self.reply(200, IMDS_TOKEN.encode())
            self.reply(400, b"")

        def do_GET(self):
            if self.path.startswith("/federation/credentials?"):
                # IAM Identity Center portal: the bearer token must be the cached one.
                from urllib.parse import parse_qs, urlparse
                query = {k: v[0] for k, v in parse_qs(urlparse(self.path).query).items()}
                if self.headers.get("x-amz-sso_bearer_token") != SSO_TOKEN:
                    return self.reply(401, {"message": "Session token not found or invalid"})
                if query != {"account_id": ACCOUNT, "role_name": "IPGSigner"}:
                    return self.reply(403, {"message": "No access"})
                secret, token = TEMPORARY["ASIAIPGSSOEXAMPLE001"]
                return self.reply(200, {"roleCredentials": {"accessKeyId": "ASIAIPGSSOEXAMPLE001",
                                  "secretAccessKey": secret, "sessionToken": token, "expiration": 4102444800000}})
            if self.path == "/ecs-credentials":
                if self.headers.get("authorization") != CONTAINER_TOKEN:
                    return self.reply(401, b"")
                return self.reply(200, document("ASIAIPGECSEXAMPLE001"))
            # IMDSv2 only: every metadata read needs the session token.
            if self.headers.get("x-aws-ec2-metadata-token") != IMDS_TOKEN:
                return self.reply(401, b"")
            if self.path == "/latest/meta-data/iam/security-credentials/":
                return self.reply(200, ROLE.encode())
            if self.path == f"/latest/meta-data/iam/security-credentials/{ROLE}":
                return self.reply(200, document("ASIAIPGIMDSEXAMPLE01"))
            self.reply(404, b"")

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def exercise(executable, emulator, port, directory):
    environment = {k: v for k, v in os.environ.items() if not k.startswith(("AWS_", "IPG_"))}
    environment.update(IPG_KMS_ENDPOINT=f"http://127.0.0.1:{port}", AWS_ACCESS_KEY_ID=ACCESS_KEY,
                       AWS_SECRET_ACCESS_KEY=SECRET_KEY, AWS_SESSION_TOKEN="ipg-test-session")
    calls = 0

    def put(name, value):
        path = directory / name
        path.write_bytes(value if isinstance(value, bytes) else json.dumps(value).encode())
        return str(path)

    def call(operation, expect_ok=True, env=None, **arguments):
        nonlocal calls
        request = {"protocol": "ipg/1", "id": operation, "request": {"operation": operation, **arguments}}
        result = subprocess.run([str(executable), "call"], input=json.dumps(request).encode(), capture_output=True,
                                timeout=60, env=env or environment)
        calls += 1
        response = json.loads(result.stdout)
        assert response["ok"] is expect_ok, response
        return response.get("result") or response.get("error")

    agree, sign = emulator.create("KEY_AGREEMENT"), emulator.create("SIGN_VERIFY")
    bound = call("kms.key.bind", region=REGION, encryption_key_arn=agree, signing_key_arn=sign,
                 output=str(directory / "kms.json"))
    assert bound["provider"] == "kms" and bound["custody"] == "service", bound
    assert bound["protection"]["possession_verified"] is True and bound["attested"] is False
    fingerprint, key_path = bound["fingerprint"], str(directory / "kms.json")
    assert call("inspect", input=key_path)["format"] == "ipg-kms-key-v1"
    public = call("key.public", key=key_path, output=str(directory / "public"))
    assert public["custody"] == "service"

    message = b"kms-backed \x00\xff content"
    call("encrypt", input=put("plain", message), output=str(directory / "envelope"),
         recipient=str(directory / "public"), expected_fingerprint=fingerprint)
    decrypted = call("decrypt", input=str(directory / "envelope"), output=str(directory / "decrypted"), key=key_path)
    assert decrypted["custody"] == "service" and (directory / "decrypted").read_bytes() == message
    call("sign", input=str(directory / "plain"), output=str(directory / "signature"), key=key_path)
    call("verify", input=str(directory / "plain"), signature=str(directory / "signature"),
         signer=str(directory / "public"), expected_fingerprint=fingerprint)
    # The signature also verifies independently against the KMS public key.
    signature = json.loads((directory / "signature").read_text())
    raw = bytes.fromhex(signature["signature"])
    r, s = int.from_bytes(raw[:48], "big"), int.from_bytes(raw[48:], "big")
    framed = b"IPG detached signature v1 ecdsa-p384-sha384" + len(fingerprint).to_bytes(8, "big") + \
        fingerprint.encode() + len(message).to_bytes(8, "big") + message
    serialization.load_der_public_key(emulator.public_der(sign)).verify(
        encode_dss_signature(r, s), framed, ec.ECDSA(hashes.SHA384()))
    call("key.revoke", key=key_path, output=str(directory / "revocation"), expected_fingerprint=fingerprint,
         reason="superseded")
    call("revocation.verify", input=str(directory / "revocation"), signer=str(directory / "public"),
         expected_fingerprint=fingerprint)

    # Post-quantum signatures: a third ML_DSA_65 key makes a composite identity.
    pq = emulator.create("SIGN_VERIFY", "ML_DSA_65")
    pq_key = str(directory / "kms-pq.json")
    bound = call("kms.key.bind", region=REGION, encryption_key_arn=agree, signing_key_arn=sign,
                 mldsa_signing_key_arn=pq, output=pq_key)
    pq_fingerprint = bound["fingerprint"]
    assert pq_fingerprint != fingerprint and bound["protection"]["possession_verified"] is True
    pq_public = call("key.public", key=pq_key, output=str(directory / "pq-public"))
    assert json.loads((directory / "pq-public").read_text())["format"] == "ipg-public-p384-mldsa65-v1"
    assert pq_public["custody"] == "service"
    large = put("large", bytes(range(256)) * 64)  # 16 KiB: above KMS's 4 KiB RAW limit
    before = emulator.calls.count("Sign/EXTERNAL_MU")
    call("sign", input=large, output=str(directory / "pq-signature"), key=pq_key)
    assert emulator.calls.count("Sign/EXTERNAL_MU") == before + 1
    call("verify", input=large, signature=str(directory / "pq-signature"), signer=str(directory / "pq-public"),
         expected_fingerprint=pq_fingerprint)
    # Both halves verify independently: ECDSA with the KMS P-384 key, and ML-DSA as an
    # ordinary pure FIPS 204 signature with IPG's context over the framed message.
    pq_signature = json.loads((directory / "pq-signature").read_text())
    assert pq_signature["algorithm"] == "ecdsa-p384-mldsa65"
    raw = bytes.fromhex(pq_signature["signature"])
    content = Path(large).read_bytes()
    framed = b"IPG detached signature v1 ecdsa-p384-mldsa65" + len(pq_fingerprint).to_bytes(8, "big") + \
        pq_fingerprint.encode() + len(content).to_bytes(8, "big") + content
    serialization.load_der_public_key(emulator.public_der(sign)).verify(
        encode_dss_signature(int.from_bytes(raw[:48], "big"), int.from_bytes(raw[48:96], "big")),
        framed, ec.ECDSA(hashes.SHA384()))
    emulator.keys[pq]["key"].public_key().verify(raw[96:], framed, b"IPG ecdsa-p384-mldsa65 v1")
    # Encryption is unchanged P-384 ECDH in KMS.
    call("encrypt", input=str(directory / "plain"), output=str(directory / "pq-envelope"),
         recipient=str(directory / "pq-public"), expected_fingerprint=pq_fingerprint)
    call("decrypt", input=str(directory / "pq-envelope"), output=str(directory / "pq-decrypted"), key=pq_key)
    assert (directory / "pq-decrypted").read_bytes() == message
    call("key.revoke", key=pq_key, output=str(directory / "pq-revocation"), expected_fingerprint=pq_fingerprint,
         reason="retired")
    call("revocation.verify", input=str(directory / "pq-revocation"), signer=str(directory / "pq-public"),
         expected_fingerprint=pq_fingerprint)
    # The ML-DSA slot requires an ML_DSA_65 key, the P-384 slots refuse one, and keys are distinct.
    for arguments, code in [
        ({"signing_key_arn": sign, "mldsa_signing_key_arn": emulator.create("SIGN_VERIFY")}, "mechanism_unsupported"),
        ({"signing_key_arn": pq, "mldsa_signing_key_arn": pq}, "invalid_request"),
        ({"signing_key_arn": pq}, "mechanism_unsupported"),
    ]:
        refused = call("kms.key.bind", False, region=REGION, encryption_key_arn=agree,
                       output=str(directory / "never"), **arguments)
        assert refused["code"] == code, (arguments, refused)
    # Dropping the ML-DSA key from the file cannot downgrade the identity.
    downgraded = json.loads(Path(pq_key).read_text())
    del downgraded["mldsa_signing_key_arn"]
    assert call("sign", False, input=str(directory / "plain"), output=str(directory / "never"),
                key=put("downgraded", downgraded))["code"] == "invalid_format"

    # Refusals.
    bad = dict(environment, AWS_SECRET_ACCESS_KEY="wrong-secret")
    assert call("sign", False, env=bad, input=str(directory / "plain"), output=str(directory / "never"),
                key=key_path)["code"] == "authentication_failed"
    assert call("sign", False, input=str(directory / "plain"), output=str(directory / "never"), key=key_path,
                passphrase_file=put("pin", b"1234"))["code"] == "invalid_request"
    swapped = call("kms.key.bind", False, region=REGION, encryption_key_arn=sign, signing_key_arn=agree,
                   output=str(directory / "swapped"))
    assert swapped["code"] == "policy_mismatch", swapped
    alias = f"arn:aws-us-gov:kms:{REGION}:{ACCOUNT}:alias/ipg"
    assert call("kms.key.bind", False, region=REGION, encryption_key_arn=alias, signing_key_arn=sign,
                output=str(directory / "alias"))["code"] == "invalid_request"
    missing = f"arn:aws-us-gov:kms:{REGION}:{ACCOUNT}:key/{uuid.uuid4()}"
    assert call("kms.key.bind", False, region=REGION, encryption_key_arn=missing, signing_key_arn=sign,
                output=str(directory / "missing"))["code"] == "hardware_not_found"
    # Credential chain: instance profile (IMDSv2) and container credentials.
    credentials_server = serve_credentials()
    source = f"http://127.0.0.1:{credentials_server.server_address[1]}"
    chain = {k: v for k, v in environment.items() if not k.startswith("AWS_")}
    chain["AWS_SHARED_CREDENTIALS_FILE"] = str(directory / "no-such-credentials-file")
    imds = dict(chain, AWS_EC2_METADATA_SERVICE_ENDPOINT=source)
    call("sign", env=imds, input=str(directory / "plain"), output=str(directory / "sig-imds"), key=key_path)
    container = dict(chain, AWS_CONTAINER_CREDENTIALS_FULL_URI=f"{source}/ecs-credentials",
                     AWS_CONTAINER_AUTHORIZATION_TOKEN=CONTAINER_TOKEN, AWS_EC2_METADATA_DISABLED="true")
    call("sign", env=container, input=str(directory / "plain"), output=str(directory / "sig-container"), key=key_path)
    token_file = put("web-identity-token", WEB_IDENTITY_TOKEN.encode())
    web = dict(chain, AWS_WEB_IDENTITY_TOKEN_FILE=token_file, AWS_ROLE_ARN=ROLE_ARN,
               AWS_ENDPOINT_URL_STS=source, AWS_EC2_METADATA_DISABLED="true")
    call("sign", env=web, input=str(directory / "plain"), output=str(directory / "sig-web"), key=key_path)
    bad_token = dict(web, AWS_WEB_IDENTITY_TOKEN_FILE=put("bad-token", b"forged"))
    assert call("sign", False, env=bad_token, input=str(directory / "plain"), output=str(directory / "never"),
                key=key_path)["code"] == "authentication_failed"
    # IAM Identity Center: a profile with an sso-session and a token cached by `aws sso login`.
    home = directory / "home"
    (home / ".aws" / "sso" / "cache").mkdir(parents=True)
    (home / ".aws" / "config").write_text(
        "[profile ipg-sso]\nsso_session = corp\nsso_account_id = %s\nsso_role_name = IPGSigner\n"
        "[sso-session corp]\nsso_start_url = %s\nsso_region = %s\n" % (ACCOUNT, SSO_START_URL, REGION))

    def cache(token, expires):
        (home / ".aws" / "sso" / "cache" / "0123abcd.json").write_text(json.dumps(
            {"startUrl": SSO_START_URL, "region": REGION, "accessToken": token, "expiresAt": expires}))

    sso = dict(chain, AWS_PROFILE="ipg-sso", HOME=str(home), USERPROFILE=str(home),
               AWS_ENDPOINT_URL_SSO=source, AWS_EC2_METADATA_DISABLED="true")
    sso.pop("AWS_SHARED_CREDENTIALS_FILE", None)
    cache(SSO_TOKEN, "2099-01-01T00:00:00Z")
    call("sign", env=sso, input=str(directory / "plain"), output=str(directory / "sig-sso"), key=key_path)
    cache(SSO_TOKEN, "2001-01-01T00:00:00Z")
    assert call("sign", False, env=sso, input=str(directory / "plain"), output=str(directory / "never"),
                key=key_path)["code"] == "provider_unavailable"
    cache("revoked-token", "2099-01-01T00:00:00Z")
    assert call("sign", False, env=sso, input=str(directory / "plain"), output=str(directory / "never"),
                key=key_path)["code"] == "authentication_failed"
    for env in [dict(container, AWS_CONTAINER_AUTHORIZATION_TOKEN="wrong"),
                dict(container, AWS_CONTAINER_CREDENTIALS_FULL_URI="http://example.com/ecs-credentials"),
                dict(chain, AWS_EC2_METADATA_DISABLED="true")]:
        assert call("sign", False, env=env, input=str(directory / "plain"), output=str(directory / "never"),
                    key=key_path)["code"] == "provider_unavailable"
    credentials_server.shutdown()
    no_endpoint = {k: v for k, v in environment.items() if k != "IPG_KMS_ENDPOINT"}
    no_endpoint["IPG_KMS_ENDPOINT"] = "http://kms.example.com"
    assert call("sign", False, env=no_endpoint, input=str(directory / "plain"), output=str(directory / "never"),
                key=key_path)["code"] == "provider_unavailable"
    assert not (directory / "never").exists()

    # MCP custody: non-exportable accepts KMS keys, hardware refuses them.
    for custody, expected in [("non-exportable", True), ("hardware", False)]:
        messages = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-11-25",
             "capabilities": {}, "clientInfo": {"name": "kms", "version": "1"}}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "ipg_sign", "arguments": {
                "input": str(directory / "plain"), "output": str(directory / f"mcp-{custody}"), "key": key_path}}},
        ]
        result = subprocess.run([str(executable), "mcp", "--key-custody", custody], capture_output=True, timeout=60,
                                input=b"".join(json.dumps(m).encode() + b"\n" for m in messages), env=environment)
        calls += 1
        content = json.loads(result.stdout.splitlines()[1])["result"]["structuredContent"]
        assert content["ok"] is expected, content
        if not expected:
            assert content["error"]["code"] == "policy_mismatch"
    return calls


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ipg", type=Path, required=True, help="ipg built with --features kms")
    args = parser.parse_args()
    emulator = Emulator()
    server = serve(emulator)
    try:
        with tempfile.TemporaryDirectory() as directory:
            calls = exercise(args.ipg.resolve(), emulator, server.server_address[1], Path(directory))
    finally:
        server.shutdown()
    print(json.dumps({"ok": True, "cli_calls": calls, "kms_calls": len(emulator.calls),
                      "kms_operations": sorted(set(emulator.calls))}))


if __name__ == "__main__":
    main()
