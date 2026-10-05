"""Exercise exported IPG constraints with an independent Draft 2020-12 validator."""
import copy
import json
from pathlib import Path
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[2]
CHECKS = 0


def check(schema, value, expected=True):
    global CHECKS
    actual = Draft202012Validator(schema).is_valid(value)
    assert actual == expected, (value, list(Draft202012Validator(schema).iter_errors(value)))
    CHECKS += 1


def main():
    schemas = {name: json.loads((ROOT / f"schemas/{name}.json").read_text()) for name in ["call", "request", "response", "outcome", "formats", "mcp-tools"]}
    for name, schema in schemas.items():
        if name == "formats":
            for value in schema.values():
                Draft202012Validator.check_schema(value)
        elif name == "mcp-tools":
            for tool in schema["tools"]:
                Draft202012Validator.check_schema(tool["inputSchema"])
                Draft202012Validator.check_schema(tool["outputSchema"])
        else:
            Draft202012Validator.check_schema(schema)
    vectors = json.loads((ROOT / "tests/vectors/native-v1.json").read_text())
    for application in json.loads((ROOT / "knowledge/applications.json").read_text()):
        check(schemas["formats"]["knowledge_application"], application)
        check(schemas["formats"]["knowledge_application"], {**application, "support": "maybe"}, False)
    artifacts = [("public_key", vectors["public"]), ("secret_key", vectors["secret"]), ("validity", vectors["validity"])]
    artifacts += [("revocation", value) for value in vectors["revocations"]]
    artifacts += [(name, item[name]) for item in vectors["messages"] for name in ["envelope", "signature"]]
    artifacts += [("trust_store", item["snapshot"]) for item in vectors["snapshots"]]
    p384 = json.loads((ROOT / "tests/vectors/native-p384-v1.json").read_text())
    artifacts += [("public_key", p384["public"]), ("validity", p384["validity"])]
    artifacts += [("revocation", value) for value in p384["revocations"]]
    artifacts += [(name, item[name]) for item in p384["messages"] for name in ["envelope", "signature"]]
    artifacts += [("trust_store", item["snapshot"]) for item in p384["snapshots"]]
    hybrid = json.loads((ROOT / "tests/vectors/native-hybrid-v1.json").read_text())
    artifacts += [("public_key", hybrid["public"]), ("secret_key", hybrid["secret"]),
                  ("revocation", hybrid["revocation"]), ("validity", hybrid["validity"])]
    artifacts += [(name, item[name]) for item in hybrid["messages"] for name in ["envelope", "signature"]]
    pq = json.loads((ROOT / "tests/vectors/native-p384-mldsa65-v1.json").read_text())
    artifacts += [("public_key", pq["public"]), ("validity", pq["validity"]), ("envelope", pq["envelope"])]
    artifacts += [("revocation", value) for value in pq["revocations"]]
    artifacts += [("signature", item["signature"]) for item in pq["messages"]]
    for name, artifact in artifacts:
        schema = schemas["formats"][name]
        check(schema, artifact)
        extra = {**artifact, "unknown": True}
        check(schema, extra, False)
        for field, rule in schema["properties"].items():
            if "const" in rule:
                check(schema, {**artifact, field: "unsupported"}, False)
            if "minLength" in rule:
                width = rule["minLength"]
                for bad in ["0" * (width - 1), "0" * (width + 1), "G" * width, "A" * width, "0" * (width - 1) + "\n"]:
                    check(schema, {**artifact, field: bad}, False)
    # Suite-conditional encodings: each suite accepts only its own key and signature widths.
    v1_public, p384_public = vectors["public"], p384["public"]
    check(schemas["formats"]["public_key"], {**v1_public, "format": "ipg-public-p384-v1"}, False)
    check(schemas["formats"]["public_key"], {**p384_public, "format": "ipg-public-v1"}, False)
    # Python-style `$` matches before a final newline; variable-width fields must still refuse it.
    for name, artifact, field in [("public_key", p384_public, "fingerprint"), ("public_key", p384_public, "signing_key"),
                                  ("public_key", hybrid["public"], "encryption_key"),
                                  ("signature", hybrid["messages"][0]["signature"], "signature"),
                                  ("signature", hybrid["messages"][0]["signature"], "signer"),
                                  ("envelope", hybrid["messages"][0]["envelope"], "ephemeral_key"),
                                  ("secret_key", hybrid["secret"], "ciphertext")]:
        check(schemas["formats"][name], {**artifact, field: artifact[field] + "\n"}, False)
    check(schemas["formats"]["secret_key"],
          {**vectors["secret"], "public": {**vectors["public"], "signing_key": vectors["public"]["signing_key"] + "\n"}}, False)
    # Fingerprint width follows the suite: 64 hex for v1, 96 for P-384 and hybrid.
    assert len(p384_public["fingerprint"]) == 96 and len(v1_public["fingerprint"]) == 64
    check(schemas["formats"]["public_key"], {**p384_public, "fingerprint": p384_public["fingerprint"][:64]}, False)
    check(schemas["formats"]["public_key"], {**v1_public, "fingerprint": v1_public["fingerprint"] + "00" * 16}, False)
    check(schemas["formats"]["public_key"], {**p384_public, "signing_key": "02" + p384_public["signing_key"][2:]}, False)
    check(schemas["formats"]["secret_key"], {**vectors["secret"], "public": p384_public}, False)
    p384_envelope, v1_envelope = p384["messages"][2]["envelope"], vectors["messages"][2]["envelope"]
    check(schemas["formats"]["envelope"], {**p384_envelope, "suite": v1_envelope["suite"]}, False)
    check(schemas["formats"]["envelope"], {**v1_envelope, "suite": p384_envelope["suite"]}, False)
    for name, value in [("signature", p384["messages"][2]["signature"]), ("validity", p384["validity"]), ("revocation", p384["revocations"][0])]:
        check(schemas["formats"][name], {**value, "algorithm": "ed25519"}, False)
        check(schemas["formats"][name], {**value, "algorithm": "ecdsa-p256-sha256"}, False)
    # Each secret format binds exactly its own identity suite and seed length.
    check(schemas["formats"]["secret_key"], {**hybrid["secret"], "format": "ipg-secret-v1"}, False)
    check(schemas["formats"]["secret_key"], {**vectors["secret"], "format": "ipg-secret-hybrid-v1"}, False)
    check(schemas["formats"]["secret_key"], {**hybrid["secret"], "public": v1_public}, False)
    check(schemas["formats"]["public_key"], {**hybrid["public"], "format": "ipg-public-v1"}, False)
    composite = hybrid["messages"][2]["signature"]
    check(schemas["formats"]["signature"], {**composite, "algorithm": "ed25519"}, False)
    check(schemas["formats"]["signature"], {**composite, "signature": composite["signature"][:128]}, False)
    hybrid_envelope = hybrid["messages"][2]["envelope"]
    check(schemas["formats"]["envelope"], {**hybrid_envelope, "suite": v1_envelope["suite"]}, False)
    check(schemas["formats"]["envelope"], {**v1_envelope, "suite": hybrid_envelope["suite"]}, False)
    reference = {"format": "ipg-pkcs11-key-v1", "public": p384_public,
                 "token": {"serial": "0123456789abcdef", "label": "ipg-test", "manufacturer": "Test", "model": "Oracle"},
                 "encryption_key_id": "01" * 16, "signing_key_id": "02" * 16}
    tpm_key = json.loads((ROOT / "tests/vectors/tpm-key-swtpm.json").read_text())
    tpm_schema = schemas["formats"]["tpm_key"]
    check(tpm_schema, tpm_key)
    check(tpm_schema, {**tpm_key, "parent": "another-template"}, False)
    check(tpm_schema, {**tpm_key, "unknown": True}, False)
    check(tpm_schema, {**tpm_key, "encryption_key": {**tpm_key["encryption_key"], "private": "ABC"}}, False)
    check(tpm_schema, {**tpm_key, "tpm": {**tpm_key["tpm"], "manufacturer": "TOOLONG"}}, False)
    check(tpm_schema, {**tpm_key, "signing_key": {**tpm_key["signing_key"], "public": tpm_key["signing_key"]["public"] + "\n"}}, False)
    kms_key = {"format": "ipg-kms-key-v1", "public": p384_public, "region": "us-gov-west-1",
               "encryption_key_arn": "arn:aws-us-gov:kms:us-gov-west-1:123456789012:key/11111111-1111-1111-1111-111111111111",
               "signing_key_arn": "arn:aws-us-gov:kms:us-gov-west-1:123456789012:key/22222222-2222-2222-2222-222222222222"}
    kms_schema = schemas["formats"]["kms_key"]
    check(kms_schema, kms_key)
    check(kms_schema, {**kms_key, "encryption_key_arn": "arn:aws:kms:us-east-1:123456789012:alias/ipg"}, False)
    check(kms_schema, {**kms_key, "region": "US-EAST-1"}, False)
    check(kms_schema, {**kms_key, "unknown": True}, False)
    check(kms_schema, {**kms_key, "region": "us-gov-west-1\n"}, False)
    check(kms_schema, {**kms_key, "signing_key_arn": kms_key["signing_key_arn"] + "\n"}, False)
    # Stream headers from the independent oracle's fixture streams.
    streams = json.loads((ROOT / "tests/vectors/stream-v1.json").read_text())
    header_schema = schemas["formats"]["stream_header"]
    for case in streams["cases"]:
        raw = bytes.fromhex(case["stream_hex"])
        header = json.loads(raw[12:12 + int.from_bytes(raw[8:12], "big")])
        check(header_schema, header)
        for field, bad in [("chunk_size", 1024), ("content_cipher", "aes-128-gcm"), ("format", "ipg-stream-v2"),
                           ("nonce_prefix", "00" * 8), ("stream_id", "AB" * 16), ("recipients", [])]:
            check(header_schema, {**header, field: bad}, False)
        check(header_schema, {**header, "recipients": header["recipients"] * 65}, False)
        check(header_schema, {**header, "unknown": 1}, False)
    signature_vectors = json.loads((ROOT / "tests/vectors/stream-signatures-v1.json").read_text())
    stream_signature_schema = schemas["formats"]["stream_signature"]
    for case in signature_vectors["cases"]:
        signature = case["signature"]
        check(stream_signature_schema, signature)
        for field, bad in [("format", "ipg-signature-v1"), ("digest_algorithm", "sha2-256"),
                           ("digest", "00" * 32), ("bytes", -1), ("bytes", 2**64),
                           ("signature", "00" * 63)]:
            check(stream_signature_schema, {**signature, field:bad}, False)
    # TPM attestation evidence captured from swtpm, and the protocol messages.
    evidence = json.loads((ROOT / "tests/vectors/tpm-attestation-swtpm/evidence.json").read_text())
    evidence_schema = schemas["formats"]["tpm_evidence"]
    check(evidence_schema, evidence)
    check(evidence_schema, {**evidence, "unknown": 1}, False)
    check(evidence_schema, {**evidence, "format": "ipg-tpm-evidence-v2"}, False)
    check(evidence_schema, {**evidence, "ek_certificates": []}, False)
    check(evidence_schema, {**evidence, "ek_certificates": evidence["ek_certificates"] * 5}, False)
    check(evidence_schema, {**evidence, "certifications": evidence["certifications"][:1]}, False)
    check(evidence_schema, {**evidence, "ak_public": evidence["ak_public"].upper()}, False)
    check(evidence_schema, {**evidence, "ak_public": evidence["ak_public"] + "\n"}, False)
    certification = evidence["certifications"][0]
    check(evidence_schema, {**evidence, "certifications": [{**certification, "role": "admin"}, certification]}, False)
    challenge = {"format": "ipg-tpm-challenge-v1", "fingerprint": evidence["public"]["fingerprint"],
                 "evidence_digest": "ab" * 48, "id_object": "00" * 50, "encrypted_secret": "11" * 256}
    check(schemas["formats"]["tpm_challenge"], challenge)
    check(schemas["formats"]["tpm_challenge"], {**challenge, "evidence_digest": "ab" * 32}, False)
    secret = {"format": "ipg-tpm-challenge-secret-v1", "fingerprint": evidence["public"]["fingerprint"],
              "evidence_digest": "ab" * 48, "credential": "cd" * 32}
    check(schemas["formats"]["tpm_challenge_secret"], secret)
    check(schemas["formats"]["tpm_challenge_secret"], {**secret, "credential": "cd" * 31}, False)
    response = {"format": "ipg-tpm-response-v1", "evidence_digest": "ab" * 48, "credential": "cd" * 32}
    check(schemas["formats"]["tpm_response"], response)
    check(schemas["formats"]["tpm_response"], {**response, "format": "ipg-tpm-challenge-v1"}, False)
    # The optional ML-DSA key: an exact key ARN or absent.
    pq_kms = {**kms_key, "public": pq["public"],
              "mldsa_signing_key_arn": "arn:aws-us-gov:kms:us-gov-west-1:123456789012:key/33333333-3333-3333-3333-333333333333"}
    check(kms_schema, pq_kms)
    check(kms_schema, {**pq_kms, "mldsa_signing_key_arn": "arn:aws-us-gov:kms:us-gov-west-1:123456789012:alias/pq"}, False)
    check(kms_schema, {**pq_kms, "mldsa_signing_key_arn": pq_kms["mldsa_signing_key_arn"] + "\n"}, False)
    # The composite suite's widths: its keys and signatures fit no other suite.
    pq_public, pq_signature = pq["public"], pq["messages"][0]["signature"]
    for fmt in ["ipg-public-p384-v1", "ipg-public-hybrid-v1"]:
        check(schemas["formats"]["public_key"], {**pq_public, "format": fmt}, False)
    check(schemas["formats"]["public_key"], {**p384_public, "format": "ipg-public-p384-mldsa65-v1"}, False)
    for algorithm in ["ecdsa-p384-sha384", "ed25519-mldsa65"]:
        check(schemas["formats"]["signature"], {**pq_signature, "algorithm": algorithm}, False)
    check(schemas["formats"]["signature"], {**pq_signature, "signature": pq_signature["signature"][:192]}, False)
    cng_key = {"format": "ipg-cng-key-v1", "public": p384_public, "provider": "Microsoft Platform Crypto Provider",
               "vendor": "AMD", "encryption_key_name": "ipg-" + "0" * 32 + "-enc", "signing_key_name": "ipg-" + "0" * 32 + "-sig"}
    cng_schema = schemas["formats"]["cng_key"]
    check(cng_schema, cng_key)
    check(cng_schema, {**cng_key, "provider": "Microsoft Software Key Storage Provider"}, False)
    check(cng_schema, {**cng_key, "encryption_key_name": "ipg-" + "0" * 32 + "-sig"}, False)
    check(cng_schema, {**cng_key, "signing_key_name": "ipg-" + "0" * 32 + "-sig\n"}, False)
    hardware = schemas["formats"]["hardware_key"]
    check(hardware, reference)
    check(hardware, {**reference, "unknown": True}, False)
    check(hardware, {**reference, "format": "ipg-pkcs11-key-v2"}, False)
    for field, bad in [("encryption_key_id", ""), ("encryption_key_id", "0"), ("encryption_key_id", "AB"), ("signing_key_id", "ab" * 65)]:
        check(hardware, {**reference, field: bad}, False)
    for field, bad in [("serial", ""), ("serial", "x" * 17), ("model", "x" * 17), ("label", "x" * 33)]:
        check(hardware, {**reference, "token": {**reference["token"], field: bad}}, False)
    envelope = vectors["messages"][-1]["envelope"]
    for valid in ["", "00", "abCD", envelope["ciphertext"].upper()]:
        check(schemas["formats"]["envelope"], {**envelope, "ciphertext": valid})
    for bad in ["0", "gg", "00\n", "00\r\n", " 00", "00 ", "éé"]:
        check(schemas["formats"]["envelope"], {**envelope, "ciphertext": bad}, False)
    for name in ["validity"]:
        for field, lower, upper in [("not_before", 0, 253402300798), ("not_after", 1, 253402300799)]:
            for value in [lower, upper]:
                check(schemas["formats"][name], {**vectors[name], field: value})
            for value in [lower - 1, upper + 1, "123", 1.5, None]:
                check(schemas["formats"][name], {**vectors[name], field: value}, False)
    store = copy.deepcopy(vectors["snapshots"][0]["snapshot"])
    store["entries"][0]["validity"] = vectors["validity"]
    check(schemas["formats"]["trust_store"], store, False)
    store["format"] = "ipg-trust-v2"
    check(schemas["formats"]["trust_store"], store)
    store["format"] = "ipg-trust-v3"
    check(schemas["formats"]["trust_store"], store)
    store["format"] = "ipg-trust-v4"
    check(schemas["formats"]["trust_store"], store, False)
    store["format"] = "ipg-trust-v2"
    # Shape-only fixtures: identity uniqueness is a semantic runtime check.
    store["entries"] *= 256
    check(schemas["formats"]["trust_store"], store)
    store["entries"].append(store["entries"][0])
    check(schemas["formats"]["trust_store"], store, False)
    openpgp_key = {"format": "ipg-openpgp-key-v1", "fingerprint": "ab" * 20, "algorithm": "ed25519",
                   "user_id": "Alice <alice@example.test>", "certificate": "99" * 300,
                   "kdf": "argon2id-m65536-t3-p4", "salt": "00" * 16, "nonce": "00" * 12, "ciphertext": "01" * 200,
                   "tag": "00" * 16}
    openpgp_schema = schemas["formats"]["openpgp_key"]
    check(openpgp_schema, openpgp_key)
    check(openpgp_schema, {**openpgp_key, "fingerprint": "ab" * 32})
    for field, bad in [("format", "ipg-secret-v1"), ("fingerprint", "AB" * 20), ("fingerprint", "ab" * 31),
                       ("algorithm", "rsa"), ("certificate", "999"), ("certificate", "99" * 16385),
                       ("ciphertext", "01" * 4097), ("kdf", "pbkdf2"), ("salt", "00" * 15), ("user_id", "a\nb")]:
        check(openpgp_schema, {**openpgp_key, field: bad}, False)
    check(openpgp_schema, {**openpgp_key, "extra": 1}, False)
    tools = {tool["name"]: tool["inputSchema"] for tool in schemas["mcp-tools"]["tools"]}
    pin = "ab" * 32
    policy = {"store": "snapshot", "expected_digest": pin}
    operations = 0
    for variant in schemas["request"]["oneOf"]:
        operation = variant["properties"]["operation"]["const"]
        values = {"operation": operation}
        defaults = {"request": {"operation": "hash", "input": "missing"}, "base": policy, "candidate": policy, "incoming": policy, "expected_fingerprint": pin, "expected_digest": pin, "not_before": 0, "not_after": 1, "at_time": 0, "reason": "retired", "encryption_key_id": "01" * 16, "signing_key_id": "02" * 16, "region": "us-east-1", "encryption_key_arn": "arn:aws:kms:us-east-1:123456789012:key/1", "signing_key_arn": "arn:aws:kms:us-east-1:123456789012:key/2", "user_id": "Alice <alice@example.test>", "expected_openpgp_fingerprint": "AB" * 20, "expected_subject_fingerprint": pin, "expected_root_fingerprint": pin, "operations": ["sign"], "recipients": [{"certificate": "path", "expected_openpgp_fingerprint": "ab" * 20}]}
        for field in variant["required"]:
            if field != "operation":
                values[field] = defaults.get(field, "path")
        if operation == "stream.encrypt":
            values["recipients"] = [{"public": "path", "expected_fingerprint": pin}]
        check(schemas["request"], values)
        call = {"protocol": "ipg/1", "id": "schema", "request": values}
        check(schemas["call"], call)
        check(schemas["call"], {**call, "protocol": "ipg/2"}, False)
        arguments = {k: v for k, v in values.items() if k != "operation"}
        tool_schema = tools["ipg_" + operation.replace(".", "_")]
        check(tool_schema, arguments)
        if operation == "knowledge.search":
            for query, valid in [("", False), ("a" * 257, False), ("é" * 256, True), ("file digest", True)]:
                check(tool_schema, {"query": query}, valid)
        for field in ["expected_fingerprint", "expected_digest"]:
            if field in values:
                for bad in ["short", pin.upper(), "g" * 64, pin + "\n", ("ab" * 48) + "\n"]:
                    malformed = {**values, field: bad}
                    check(schemas["request"], malformed, False)
                    check(schemas["request"], {"operation": "plan", "request": malformed}, False)
                    check(tool_schema, {**arguments, field: bad}, False)
        for field in ["base", "candidate", "incoming", "policy"]:
            if field in variant["properties"]:
                check(tool_schema, {**arguments, field: {"store": "snapshot", "expected_digest": "bad"}}, False)
        for field in ["not_before", "not_after", "at_time"]:
            if field in values:
                for bad in [-1, 253402300800, "123", 1.5]:
                    check(tool_schema, {**arguments, field: bad}, False)
        for field in ["encryption_key_id", "signing_key_id"]:
            if field in values:
                for bad in ["", "0", "AB", "ab" * 65, "abab\n"]:
                    check(tool_schema, {**arguments, field: bad}, False)
        if operation == "kms.key.bind":
            for bad in ["alias", "arn:aws:kms:us-east-1:123:key/1", "arn:aws:s3:us-east-1:123456789012:key/1"]:
                check(tool_schema, {**arguments, "encryption_key_arn": bad}, False)
                check(tool_schema, {**arguments, "mldsa_signing_key_arn": bad}, False)
            check(tool_schema, {**arguments, "mldsa_signing_key_arn": "arn:aws:kms:us-east-1:123456789012:key/3"})
        if "expected_openpgp_fingerprint" in values:
            # Either case and both defined widths are valid; spaces and trailing newlines are not.
            check(tool_schema, {**arguments, "expected_openpgp_fingerprint": "ab" * 20})
            check(tool_schema, {**arguments, "expected_openpgp_fingerprint": "AB" * 32})
            for bad in ["ab" * 31, "g" * 40, ("ab" * 20) + "\n", " ".join(["ABCD"] * 10), "ab" * 19]:
                check(tool_schema, {**arguments, "expected_openpgp_fingerprint": bad}, False)
        if operation == "stream.encrypt":
            recipient = values["recipients"][0]
            check(tool_schema, {**arguments, "recipients": [recipient] * 64})
            for bad in [[], [recipient] * 65, [{"public": "path"}], [{**recipient, "expected_fingerprint": "AB" * 32}],
                        [{"certificate": "path", "expected_openpgp_fingerprint": "ab" * 20}]]:
                check(tool_schema, {**arguments, "recipients": bad}, False)
        if operation == "openpgp.encrypt":
            recipient = values["recipients"][0]
            for bad in [[], [recipient] * 33, [{"certificate": "path"}], [{**recipient, "extra": 1}],
                        [{**recipient, "expected_openpgp_fingerprint": "ab" * 31}]]:
                check(tool_schema, {**arguments, "recipients": bad}, False)
            check(tool_schema, {**arguments, "recipients": [recipient] * 32})
        if "user_id" in values:
            for bad in ["", "line\nbreak", "tab\there", "c1\u0085control", "x" * 257]:
                check(tool_schema, {**arguments, "user_id": bad}, False)
            check(tool_schema, {**arguments, "user_id": "Ünïcode Name <u@example.test>"})
            check(tool_schema, {**arguments, "algorithm": "p384"})
            check(tool_schema, {**arguments, "algorithm": "rsa4096"}, False)
            check(tool_schema, {**arguments, "key_version": "v4"})
            check(tool_schema, {**arguments, "key_version": "v6"})
            check(tool_schema, {**arguments, "key_version": "v5"}, False)
        if "token_serial" in values:
            for bad in ["", "x" * 17]:
                check(tool_schema, {**arguments, "token_serial": bad}, False)
        operations += 1
    print(json.dumps({"ok": True, "schema_checks": CHECKS, "operations": operations}))


if __name__ == "__main__":
    main()
