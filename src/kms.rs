//! AWS KMS backend. Private keys stay in KMS; IPG sends digests to sign and peer
//! public keys to agree with. Requests use SigV4 with the host's AWS credentials over
//! TLS from rustls with IronCrypto's provider, so no C code is compiled.
//!
//! Only binding of existing keys is offered: KMS keys are billable account resources,
//! created by infrastructure tooling rather than agent-callable requests.
use crate::{
    crypto::{self, Custody, IdentityKey, PublicKey, Suite},
    error::{Error, Result},
    provider::{self, KmsKey, Protection},
};
use ic_core::traits::{Digest as _, Mac};
use ic_hash::Sha256;
use ic_mac::HmacSha256;
use serde_json::{Value, json};
use std::{
    io::{Read, Write},
    net::TcpStream,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;

const MAX_RESPONSE_BYTES: u64 = 1024 * 1024;
/// DER SubjectPublicKeyInfo prefix for an uncompressed named-curve P-384 point.
const P384_SPKI_PREFIX: [u8; 23] = [
    0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b,
    0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00,
];

pub struct Credentials {
    access_key: String,
    secret_key: Zeroizing<String>,
    session_token: Option<Zeroizing<String>>,
}

/// The AWS credential chain, in SDK order: environment variables, web identity
/// federation, a static profile in the shared credentials file, an IAM Identity
/// Center (SSO) profile with a cached `aws sso login` token, container credentials
/// (ECS task roles, EKS Pod Identity), then EC2 instance-profile credentials through
/// IMDSv2.
fn credentials(region: &str, partition: &str) -> Result<Credentials> {
    let env = |name| std::env::var(name).ok().filter(|v: &String| !v.is_empty());
    if let (Some(access_key), Some(secret)) =
        (env("AWS_ACCESS_KEY_ID"), env("AWS_SECRET_ACCESS_KEY"))
    {
        return Ok(Credentials {
            access_key,
            secret_key: Zeroizing::new(secret),
            session_token: env("AWS_SESSION_TOKEN").map(Zeroizing::new),
        });
    }
    if let Some(credentials) = web_identity_credentials(region, partition)? {
        return Ok(credentials);
    }
    if let Some(credentials) = shared_file_credentials()? {
        return Ok(credentials);
    }
    if let Some(credentials) = sso_credentials()? {
        return Ok(credentials);
    }
    if let Some(credentials) = container_credentials()? {
        return Ok(credentials);
    }
    if !env("AWS_EC2_METADATA_DISABLED").is_some_and(|v| v.eq_ignore_ascii_case("true"))
        && let Some(credentials) = instance_credentials()?
    {
        return Ok(credentials);
    }
    Err(unavailable())
}

/// A static profile (`AWS_PROFILE`, default `default`) from `AWS_SHARED_CREDENTIALS_FILE`
/// or `~/.aws/credentials`. A missing file or profile is not an error.
fn shared_file_credentials() -> Result<Option<Credentials>> {
    let env = |name| std::env::var(name).ok().filter(|v: &String| !v.is_empty());
    let Some(path) = env("AWS_SHARED_CREDENTIALS_FILE")
        .map(std::path::PathBuf::from)
        .or_else(|| {
            std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" })
                .map(|home| std::path::Path::new(&home).join(".aws").join("credentials"))
        })
    else {
        return Ok(None);
    };
    let Ok(file) = std::fs::File::open(&path) else {
        return Ok(None);
    };
    let profile = env("AWS_PROFILE").unwrap_or_else(|| "default".into());
    let text = Zeroizing::new(
        String::from_utf8(crate::read_limited(file, 65536)?.to_vec())
            .map_err(|_| Error::new("provider_unavailable", "AWS credentials file is not UTF-8"))?,
    );
    let (mut section, mut access_key, mut secret, mut token) = (String::new(), None, None, None);
    for line in text.lines().map(str::trim) {
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            section = name.trim().into();
        } else if section == profile
            && let Some((key, value)) = line.split_once('=')
        {
            let value = value.trim().to_string();
            match key.trim() {
                "aws_access_key_id" => access_key = Some(value),
                "aws_secret_access_key" => secret = Some(Zeroizing::new(value)),
                "aws_session_token" => token = Some(Zeroizing::new(value)),
                _ => {}
            }
        }
    }
    Ok(match (access_key, secret) {
        (Some(access_key), Some(secret_key)) => Some(Credentials {
            access_key,
            secret_key,
            session_token: token,
        }),
        _ => None,
    })
}

fn home() -> Option<std::path::PathBuf> {
    std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" })
        .filter(|v| !v.is_empty())
        .map(std::path::PathBuf::from)
}

/// `key = value` pairs of one section of an AWS INI file.
fn ini_section(text: &str, section: &str) -> Option<std::collections::BTreeMap<String, String>> {
    let (mut current, mut found, mut values) =
        (String::new(), false, std::collections::BTreeMap::new());
    for line in text.lines().map(str::trim) {
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            current = name.split_whitespace().collect::<Vec<_>>().join(" ");
            found |= current == section;
        } else if current == section
            && let Some((key, value)) = line.split_once('=')
        {
            values.insert(key.trim().to_string(), value.trim().to_string());
        }
    }
    found.then_some(values)
}

/// Unix seconds from an RFC 3339 UTC timestamp `YYYY-MM-DDTHH:MM:SS[.fff](Z|UTC)`.
pub(crate) fn unix_time(text: &str) -> Option<u64> {
    let number = |range: std::ops::Range<usize>| text.get(range)?.parse::<i64>().ok();
    let (year, month, day) = (number(0..4)?, number(5..7)?, number(8..10)?);
    let (hour, minute, second) = (number(11..13)?, number(14..16)?, number(17..19)?);
    if text.get(4..5)? != "-" || text.get(10..11)? != "T" || !(1..=12).contains(&month) {
        return None;
    }
    let rest = &text[19..];
    let rest = rest
        .strip_prefix('.')
        .map_or(rest, |r| r.trim_start_matches(|c: char| c.is_ascii_digit()));
    if !matches!(rest, "Z" | "UTC" | "+00:00") {
        return None;
    }
    // Days from civil (proleptic Gregorian), inverse of amz_date.
    let y = year - i64::from(month <= 2);
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    u64::try_from(days * 86400 + hour * 3600 + minute * 60 + second).ok()
}

/// IAM Identity Center credentials for a profile in `AWS_CONFIG_FILE` or
/// `~/.aws/config` with `sso_account_id`, `sso_role_name` and either an
/// `sso_session` or legacy `sso_start_url`/`sso_region`. Uses the token cached by
/// `aws sso login`; IPG never refreshes or creates SSO tokens.
fn sso_credentials() -> Result<Option<Credentials>> {
    let env = |name| std::env::var(name).ok().filter(|v: &String| !v.is_empty());
    let Some(config) = env("AWS_CONFIG_FILE")
        .map(std::path::PathBuf::from)
        .or_else(|| home().map(|h| h.join(".aws").join("config")))
    else {
        return Ok(None);
    };
    let Ok(file) = std::fs::File::open(&config) else {
        return Ok(None);
    };
    let text = String::from_utf8(crate::read_limited(file, 65536)?.to_vec())
        .map_err(|_| Error::new("provider_unavailable", "AWS config file is not UTF-8"))?;
    let profile = env("AWS_PROFILE").unwrap_or_else(|| "default".into());
    let section = if profile == "default" {
        "default".to_string()
    } else {
        format!("profile {profile}")
    };
    let Some(values) = ini_section(&text, &section) else {
        return Ok(None);
    };
    let (Some(account), Some(role)) = (values.get("sso_account_id"), values.get("sso_role_name"))
    else {
        return Ok(None);
    };
    let session = match values.get("sso_session") {
        Some(name) => ini_section(&text, &format!("sso-session {name}")).ok_or_else(|| {
            Error::new(
                "provider_unavailable",
                "AWS profile names a missing sso-session",
            )
        })?,
        None => values.clone(),
    };
    let (Some(start_url), Some(region)) = (session.get("sso_start_url"), session.get("sso_region"))
    else {
        return Err(Error::new(
            "provider_unavailable",
            "SSO profile lacks sso_start_url or sso_region",
        ));
    };
    let expired = || {
        Error::new(
            "provider_unavailable",
            "No unexpired AWS SSO token for this profile; run `aws sso login`",
        )
    };
    // Pick the matching cached token with the latest expiry.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| expired())?
        .as_secs();
    let cache = home()
        .ok_or_else(expired)?
        .join(".aws")
        .join("sso")
        .join("cache");
    let mut token: Option<(u64, Zeroizing<String>)> = None;
    for entry in std::fs::read_dir(&cache).map_err(|_| expired())?.flatten() {
        let Ok(file) = std::fs::File::open(entry.path()) else {
            continue;
        };
        let Ok(data) = crate::read_limited(file, 65536) else {
            continue;
        };
        let Ok(value) = serde_json::from_slice::<Value>(&data) else {
            continue;
        };
        let (Some(url), Some(access), Some(expires)) = (
            value["startUrl"].as_str(),
            value["accessToken"].as_str(),
            value["expiresAt"].as_str().and_then(unix_time),
        ) else {
            continue;
        };
        if url == start_url
            && expires > now + 60
            && token.as_ref().is_none_or(|(t, _)| expires > *t)
        {
            token = Some((expires, Zeroizing::new(access.to_string())));
        }
    }
    let (_, token) = token.ok_or_else(expired)?;
    let endpoint = match env("AWS_ENDPOINT_URL_SSO") {
        Some(url) => {
            let (endpoint, _) = if url.starts_with("https://") {
                let authority = url.trim_start_matches("https://").trim_end_matches('/');
                let (host, port) = authority
                    .rsplit_once(':')
                    .map_or((authority.to_string(), 443), |(h, p)| {
                        (h.to_string(), p.parse().unwrap_or(443))
                    });
                (
                    Endpoint {
                        tls: true,
                        host,
                        port,
                    },
                    String::new(),
                )
            } else {
                http_url(&url).ok_or_else(|| {
                    Error::new("provider_unavailable", "Invalid AWS_ENDPOINT_URL_SSO")
                })?
            };
            if !endpoint.tls && !matches!(endpoint.host.as_str(), "localhost" | "127.0.0.1" | "::1")
            {
                return Err(Error::new(
                    "provider_unavailable",
                    "Plain-HTTP AWS endpoints are allowed only on loopback",
                ));
            }
            endpoint
        }
        None => Endpoint {
            tls: true,
            host: format!("portal.sso.{region}.amazonaws.com"),
            port: 443,
        },
    };
    let host = if (endpoint.tls && endpoint.port == 443) || (!endpoint.tls && endpoint.port == 80) {
        endpoint.host.clone()
    } else {
        format!("{}:{}", endpoint.host, endpoint.port)
    };
    let request = Zeroizing::new(
        format!(
            "GET /federation/credentials?account_id={}&role_name={} HTTP/1.1\r\nhost: {host}\r\nx-amz-sso_bearer_token: {}\r\nconnection: close\r\n\r\n",
            form(account),
            form(role),
            token.as_str()
        )
        .into_bytes(),
    );
    let (status, body) = parse_response(&transport(&endpoint, &request)?)?;
    if status == 401 || status == 403 {
        return Err(Error::new(
            "authentication_failed",
            "AWS SSO rejected the cached token or role; run `aws sso login`",
        ));
    }
    if status != 200 {
        return Err(Error::new(
            "provider_unavailable",
            format!("AWS SSO portal returned HTTP {status}"),
        ));
    }
    let value: Value = serde_json::from_slice(&body)
        .map_err(|_| Error::new("provider_unavailable", "Malformed AWS SSO response"))?;
    let role = &value["roleCredentials"];
    let field = |name: &str| {
        role[name]
            .as_str()
            .filter(|v| !v.is_empty())
            .map(String::from)
    };
    let invalid = || Error::new("provider_unavailable", "Malformed AWS SSO response");
    Ok(Some(Credentials {
        access_key: field("accessKeyId").ok_or_else(invalid)?,
        secret_key: Zeroizing::new(field("secretAccessKey").ok_or_else(invalid)?),
        session_token: field("sessionToken").map(Zeroizing::new),
    }))
}

/// Temporary credentials JSON as returned by IMDS and container endpoints.
fn temporary(body: &[u8]) -> Result<Credentials> {
    let invalid = || Error::new("provider_unavailable", "Malformed AWS credential response");
    let value: Value = serde_json::from_slice(body).map_err(|_| invalid())?;
    let field = |name: &str| {
        value[name]
            .as_str()
            .filter(|v| !v.is_empty())
            .map(String::from)
    };
    Ok(Credentials {
        access_key: field("AccessKeyId").ok_or_else(invalid)?,
        secret_key: Zeroizing::new(field("SecretAccessKey").ok_or_else(invalid)?),
        session_token: field("Token").map(Zeroizing::new),
    })
}

/// Parse `http://host[:port]/path`. Credential endpoints never use TLS.
fn http_url(url: &str) -> Option<(Endpoint, String)> {
    let rest = url.strip_prefix("http://")?;
    let (authority, path) = rest
        .split_once('/')
        .map_or((rest, "/".to_string()), |(a, p)| (a, format!("/{p}")));
    let (host, port) = if let Some(host) = authority.strip_prefix('[') {
        let (host, rest) = host.split_once(']')?;
        (
            host.to_string(),
            rest.strip_prefix(':')
                .map_or(Some(80), |p| p.parse().ok())?,
        )
    } else {
        match authority.rsplit_once(':') {
            Some((host, port)) => (host.to_string(), port.parse().ok()?),
            None => (authority.to_string(), 80),
        }
    };
    Some((
        Endpoint {
            tls: false,
            host,
            port,
        },
        path,
    ))
}

/// Container credentials: `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` against the ECS
/// agent, or `AWS_CONTAINER_CREDENTIALS_FULL_URI` limited, like the SDKs, to loopback
/// and the ECS and EKS Pod Identity link-local agents.
fn container_credentials() -> Result<Option<Credentials>> {
    let env = |name| std::env::var(name).ok().filter(|v: &String| !v.is_empty());
    let url = if let Some(relative) = env("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI") {
        format!("http://169.254.170.2{relative}")
    } else if let Some(full) = env("AWS_CONTAINER_CREDENTIALS_FULL_URI") {
        full
    } else {
        return Ok(None);
    };
    let (endpoint, path) = http_url(&url).ok_or_else(|| {
        Error::new(
            "provider_unavailable",
            "Container credential URI must be an http:// URL",
        )
    })?;
    let allowed = endpoint.host == "169.254.170.2"
        || endpoint.host == "169.254.170.23"
        || endpoint.host == "fd00:ec2::23"
        || endpoint.host == "localhost"
        || endpoint.host.starts_with("127.")
        || endpoint.host == "::1";
    if !allowed {
        return Err(Error::new(
            "provider_unavailable",
            "Container credential host must be loopback or an ECS/EKS agent address",
        ));
    }
    let token = match env("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE") {
        Some(file) => Some(Zeroizing::new(
            String::from_utf8(crate::read_limited(std::fs::File::open(file)?, 16384)?.to_vec())
                .map_err(|_| Error::new("provider_unavailable", "Container token is not UTF-8"))?
                .trim()
                .to_string(),
        )),
        None => env("AWS_CONTAINER_AUTHORIZATION_TOKEN").map(Zeroizing::new),
    };
    let mut headers = Vec::new();
    if let Some(token) = &token {
        headers.push(("authorization", token.as_str()));
    }
    let (status, body) = http(&endpoint, "GET", &path, &headers, Duration::from_secs(5))?;
    if status != 200 {
        return Err(Error::new(
            "provider_unavailable",
            format!("Container credential endpoint returned HTTP {status}"),
        ));
    }
    temporary(&body).map(Some)
}

/// EC2 instance-profile credentials through IMDSv2 (session token required).
fn instance_credentials() -> Result<Option<Credentials>> {
    let base = std::env::var("AWS_EC2_METADATA_SERVICE_ENDPOINT")
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "http://169.254.169.254".into());
    let Some((endpoint, _)) = http_url(&base) else {
        return Err(Error::new(
            "provider_unavailable",
            "Invalid AWS_EC2_METADATA_SERVICE_ENDPOINT",
        ));
    };
    // Off EC2 the address does not answer; fail fast and report no credentials.
    let timeout = Duration::from_secs(1);
    let Ok((200, token)) = http(
        &endpoint,
        "PUT",
        "/latest/api/token",
        &[("x-aws-ec2-metadata-token-ttl-seconds", "300")],
        timeout,
    ) else {
        return Ok(None);
    };
    let token = Zeroizing::new(String::from_utf8(token).map_err(|_| unavailable())?);
    let headers = [("x-aws-ec2-metadata-token", token.as_str())];
    let path = "/latest/meta-data/iam/security-credentials/";
    let (status, roles) = http(&endpoint, "GET", path, &headers, timeout)?;
    let role = String::from_utf8(roles).unwrap_or_default();
    let role = role.lines().next().unwrap_or("").trim();
    if status != 200
        || role.is_empty()
        || !role.bytes().all(|b| b.is_ascii_graphic())
        || role.contains('/')
    {
        return Ok(None);
    }
    let (status, body) = http(
        &endpoint,
        "GET",
        &format!("{path}{role}"),
        &headers,
        timeout,
    )?;
    if status != 200 {
        return Err(Error::new(
            "provider_unavailable",
            format!("IMDS returned HTTP {status}"),
        ));
    }
    temporary(&body).map(Some)
}

/// A plain-HTTP request to a credential endpoint.
fn http(
    endpoint: &Endpoint,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    timeout: Duration,
) -> Result<(u16, Vec<u8>)> {
    let host = if endpoint.host.contains(':') {
        format!("[{}]:{}", endpoint.host, endpoint.port)
    } else {
        format!("{}:{}", endpoint.host, endpoint.port)
    };
    let mut request = format!("{method} {path} HTTP/1.1\r\nhost: {host}\r\n");
    for (name, value) in headers {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    request.push_str("content-length: 0\r\nconnection: close\r\n\r\n");
    let wire = Zeroizing::new(request.into_bytes());
    parse_response(&exchange(endpoint, &wire, timeout)?)
}

fn unavailable() -> Error {
    Error::new(
        "provider_unavailable",
        "No AWS credentials: set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY, web identity (AWS_WEB_IDENTITY_TOKEN_FILE and AWS_ROLE_ARN), a static profile, container credentials, or run with an EC2 instance profile",
    )
}

fn hex_sha256(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}
fn hmac(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    Ok(HmacSha256::mac(key, data)?.as_ref().to_vec())
}

/// AWS Signature Version 4 `Authorization` header for a request whose headers are
/// already lowercase, trimmed and sorted by name. `amz_date` is `YYYYMMDDTHHMMSSZ`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn sigv4_authorization(
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &[u8],
    region: &str,
    service: &str,
    amz_date: &str,
    access_key: &str,
    secret_key: &str,
) -> Result<String> {
    let date = &amz_date[..8];
    let canonical_headers: String = headers.iter().map(|(k, v)| format!("{k}:{v}\n")).collect();
    let signed_headers = headers
        .iter()
        .map(|(k, _)| *k)
        .collect::<Vec<_>>()
        .join(";");
    let canonical_request = format!(
        "{method}\n{path}\n\n{canonical_headers}\n{signed_headers}\n{}",
        hex_sha256(body)
    );
    let scope = format!("{date}/{region}/{service}/aws4_request");
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        hex_sha256(canonical_request.as_bytes())
    );
    let key = Zeroizing::new(format!("AWS4{secret_key}"));
    let mut signing = Zeroizing::new(hmac(key.as_bytes(), date.as_bytes())?);
    for part in [region, service, "aws4_request"] {
        signing = Zeroizing::new(hmac(&signing, part.as_bytes())?);
    }
    let signature = hex::encode(hmac(&signing, string_to_sign.as_bytes())?);
    Ok(format!(
        "AWS4-HMAC-SHA256 Credential={access_key}/{scope}, SignedHeaders={signed_headers}, Signature={signature}"
    ))
}

/// UTC `YYYYMMDDTHHMMSSZ` from Unix seconds (civil-from-days, proleptic Gregorian).
pub(crate) fn amz_date(unix: u64) -> String {
    let (days, seconds) = ((unix / 86400) as i64, unix % 86400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}{month:02}{day:02}T{:02}{:02}{:02}Z",
        seconds / 3600,
        seconds / 60 % 60,
        seconds % 60
    )
}

struct Endpoint {
    tls: bool,
    host: String,
    port: u16,
}
/// The regional (or FIPS) endpoint, unless the host overrides it. Overrides without
/// TLS are accepted only for loopback test services.
/// Resolve a service endpoint: a host override (`IPG_KMS_ENDPOINT`, or the SDK's
/// `AWS_ENDPOINT_URL_STS`), else the regional or FIPS endpoint. Overrides without TLS
/// are accepted only for loopback test services.
fn endpoint(service: &str, region: &str, partition: &str) -> Result<Endpoint> {
    let variable = if service == "kms" {
        "IPG_KMS_ENDPOINT"
    } else {
        "AWS_ENDPOINT_URL_STS"
    };
    if let Some(value) = std::env::var(variable).ok().filter(|v| !v.is_empty()) {
        let invalid = || {
            Error::new(
                "provider_unavailable",
                format!("{variable} must be an http(s)://host[:port] URL"),
            )
        };
        let (tls, rest) = if let Some(rest) = value.strip_prefix("https://") {
            (true, rest)
        } else if let Some(rest) = value.strip_prefix("http://") {
            (false, rest)
        } else {
            return Err(invalid());
        };
        let authority = rest.trim_end_matches('/');
        let (host, port) = match authority.rsplit_once(':') {
            Some((host, port)) => (host.to_string(), port.parse().map_err(|_| invalid())?),
            None => (authority.to_string(), if tls { 443 } else { 80 }),
        };
        if !tls && !matches!(host.as_str(), "localhost" | "127.0.0.1" | "[::1]") {
            return Err(Error::new(
                "provider_unavailable",
                "Plain-HTTP AWS endpoints are allowed only on loopback",
            ));
        }
        return Ok(Endpoint { tls, host, port });
    }
    let fips = std::env::var("IPG_KMS_FIPS").is_ok_and(|v| v == "1");
    let suffix = if partition == "aws-cn" {
        "amazonaws.com.cn"
    } else {
        "amazonaws.com"
    };
    Ok(Endpoint {
        tls: true,
        host: if fips {
            format!("{service}-fips.{region}.{suffix}")
        } else {
            format!("{service}.{region}.{suffix}")
        },
        port: 443,
    })
}

/// Form-encode a value for an STS query body (RFC 3986 unreserved characters kept).
fn form(value: &str) -> String {
    value
        .bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}
/// The text of the first `<tag>` element in an STS XML response, entity-decoded.
fn xml_text(xml: &str, tag: &str) -> Option<String> {
    let start = xml.find(&format!("<{tag}>"))? + tag.len() + 2;
    let end = start + xml[start..].find(&format!("</{tag}>"))?;
    Some(
        xml[start..end]
            .trim()
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&quot;", "\"")
            .replace("&apos;", "'")
            .replace("&amp;", "&"),
    )
}

/// Web identity federation (EKS IRSA, CI OIDC): exchange the token in
/// `AWS_WEB_IDENTITY_TOKEN_FILE` for role credentials with an unsigned STS
/// AssumeRoleWithWebIdentity call in the key's region.
fn web_identity_credentials(region: &str, partition: &str) -> Result<Option<Credentials>> {
    let env = |name| std::env::var(name).ok().filter(|v: &String| !v.is_empty());
    let (Some(token_file), Some(role)) = (env("AWS_WEB_IDENTITY_TOKEN_FILE"), env("AWS_ROLE_ARN"))
    else {
        return Ok(None);
    };
    let token = Zeroizing::new(
        String::from_utf8(crate::read_limited(std::fs::File::open(token_file)?, 16384)?.to_vec())
            .map_err(|_| Error::new("provider_unavailable", "Web identity token is not UTF-8"))?
            .trim()
            .to_string(),
    );
    let session = env("AWS_ROLE_SESSION_NAME").unwrap_or_else(|| "ipg".into());
    let body = Zeroizing::new(format!(
        "Action=AssumeRoleWithWebIdentity&Version=2011-06-15&RoleArn={}&RoleSessionName={}&WebIdentityToken={}",
        form(&role),
        form(&session),
        form(&token)
    ));
    let endpoint = endpoint("sts", region, partition)?;
    let host = if (endpoint.tls && endpoint.port == 443) || (!endpoint.tls && endpoint.port == 80) {
        endpoint.host.clone()
    } else {
        format!("{}:{}", endpoint.host, endpoint.port)
    };
    let mut wire = Zeroizing::new(
        format!(
            "POST / HTTP/1.1\r\nhost: {host}\r\ncontent-type: application/x-www-form-urlencoded\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes(),
    );
    wire.extend_from_slice(body.as_bytes());
    let (status, response) = parse_response(&transport(&endpoint, &wire)?)?;
    let xml = Zeroizing::new(String::from_utf8_lossy(&response).into_owned());
    if status != 200 {
        let code = xml_text(&xml, "Code").unwrap_or_default();
        return Err(Error::new(
            if status < 500 {
                "authentication_failed"
            } else {
                "provider_error"
            },
            format!("STS {status} {code}: web identity was not accepted"),
        ));
    }
    let field = |tag| xml_text(&xml, tag).filter(|v| !v.is_empty());
    let invalid = || Error::new("provider_error", "Malformed STS credential response");
    Ok(Some(Credentials {
        access_key: field("AccessKeyId").ok_or_else(invalid)?,
        secret_key: Zeroizing::new(field("SecretAccessKey").ok_or_else(invalid)?),
        session_token: Some(Zeroizing::new(field("SessionToken").ok_or_else(invalid)?)),
    }))
}

fn tls_config() -> Result<Arc<rustls::ClientConfig>> {
    let roots = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    Ok(Arc::new(
        rustls::ClientConfig::builder_with_provider(ic_rustls::arc_provider())
            .with_safe_default_protocol_versions()
            .map_err(|e| Error::new("provider_error", format!("TLS configuration: {e}")))?
            .with_root_certificates(roots)
            .with_no_client_auth(),
    ))
}

fn transport(endpoint: &Endpoint, request: &[u8]) -> Result<Vec<u8>> {
    exchange(endpoint, request, Duration::from_secs(30))
}
fn exchange(endpoint: &Endpoint, request: &[u8], timeout: Duration) -> Result<Vec<u8>> {
    use std::net::ToSocketAddrs;
    let network = |e: std::io::Error| Error {
        code: "provider_error",
        message: format!("AWS network error: {e}"),
        retryable: true,
    };
    let address = (endpoint.host.trim_matches(['[', ']']), endpoint.port)
        .to_socket_addrs()
        .map_err(network)?
        .next()
        .ok_or_else(|| network(std::io::ErrorKind::NotFound.into()))?;
    let socket = TcpStream::connect_timeout(&address, timeout).map_err(network)?;
    socket.set_read_timeout(Some(timeout)).map_err(network)?;
    socket.set_write_timeout(Some(timeout)).map_err(network)?;
    let mut response = Vec::new();
    if endpoint.tls {
        let name = rustls::pki_types::ServerName::try_from(endpoint.host.clone())
            .map_err(|_| Error::new("provider_unavailable", "Invalid KMS host name"))?;
        let connection = rustls::ClientConnection::new(tls_config()?, name)
            .map_err(|e| Error::new("provider_error", format!("TLS: {e}")))?;
        let mut stream = rustls::StreamOwned::new(connection, socket);
        stream.write_all(request).map_err(network)?;
        (&mut stream)
            .take(MAX_RESPONSE_BYTES + 1)
            .read_to_end(&mut response)
            .map_err(network)?;
    } else {
        let mut stream = socket;
        stream.write_all(request).map_err(network)?;
        (&mut stream)
            .take(MAX_RESPONSE_BYTES + 1)
            .read_to_end(&mut response)
            .map_err(network)?;
    }
    if response.len() as u64 > MAX_RESPONSE_BYTES {
        return Err(Error::new(
            "provider_error",
            "KMS response exceeds size limit",
        ));
    }
    Ok(response)
}

/// Split an HTTP/1.1 response into status and body, decoding chunked transfer.
fn parse_response(raw: &[u8]) -> Result<(u16, Vec<u8>)> {
    let malformed = || Error::new("provider_error", "Malformed KMS HTTP response");
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(malformed)?;
    let head = std::str::from_utf8(&raw[..split]).map_err(|_| malformed())?;
    let mut body = raw[split + 4..].to_vec();
    let mut lines = head.split("\r\n");
    let status: u16 = lines
        .next()
        .and_then(|l| l.split(' ').nth(1))
        .and_then(|s| s.parse().ok())
        .ok_or_else(malformed)?;
    let chunked = lines.any(|l| {
        let l = l.to_ascii_lowercase();
        l.starts_with("transfer-encoding:") && l.contains("chunked")
    });
    if chunked {
        let (mut decoded, mut rest) = (Vec::new(), &body[..]);
        loop {
            let end = rest
                .windows(2)
                .position(|w| w == b"\r\n")
                .ok_or_else(malformed)?;
            let size_text = std::str::from_utf8(&rest[..end]).map_err(|_| malformed())?;
            let size = usize::from_str_radix(size_text.split(';').next().unwrap_or("").trim(), 16)
                .map_err(|_| malformed())?;
            rest = &rest[end + 2..];
            if size == 0 {
                break;
            }
            decoded.extend_from_slice(rest.get(..size).ok_or_else(malformed)?);
            rest = rest.get(size + 2..).ok_or_else(malformed)?;
        }
        body = decoded;
    }
    Ok((status, body))
}

pub(crate) fn base64(data: &[u8]) -> String {
    crate::base64::encode(data)
}
pub(crate) fn unbase64(text: &str) -> Result<Vec<u8>> {
    crate::base64::decode(text)
        .map_err(|_| Error::new("provider_error", "Invalid base64 in KMS response"))
}

fn kms_error(status: u16, body: &[u8]) -> Error {
    let parsed: Value = serde_json::from_slice(body).unwrap_or(Value::Null);
    let kind = parsed["__type"]
        .as_str()
        .unwrap_or("")
        .rsplit('#')
        .next()
        .unwrap_or("")
        .to_string();
    let message = parsed["message"]
        .as_str()
        .or(parsed["Message"].as_str())
        .unwrap_or("")
        .chars()
        .take(300)
        .collect::<String>();
    let detail = format!("KMS {status} {kind}: {message}");
    let (code, retryable) = match kind.as_str() {
        "AccessDeniedException"
        | "UnrecognizedClientException"
        | "InvalidSignatureException"
        | "ExpiredTokenException"
        | "IncompleteSignature"
        | "InvalidClientTokenId" => ("authentication_failed", false),
        "NotFoundException" => ("hardware_not_found", false),
        "DisabledException" | "KMSInvalidStateException" | "KeyUnavailableException" => {
            ("policy_mismatch", false)
        }
        "InvalidKeyUsageException" | "UnsupportedOperationException" => {
            ("mechanism_unsupported", false)
        }
        "ThrottlingException"
        | "LimitExceededException"
        | "DependencyTimeoutException"
        | "KMSInternalException" => ("provider_error", true),
        _ => ("provider_error", status >= 500),
    };
    Error {
        code,
        message: detail,
        retryable,
    }
}

/// One signed KMS JSON call.
pub(crate) struct Client {
    region: String,
    partition: String,
}
impl Client {
    fn call(&self, action: &str, request: Value) -> Result<Value> {
        let credentials = credentials(&self.region, &self.partition)?;
        let endpoint = endpoint("kms", &self.region, &self.partition)?;
        let body = serde_json::to_vec(&request)?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::new("clock_unavailable", "Host clock precedes Unix epoch"))?
            .as_secs();
        let date = amz_date(now);
        let host =
            if (endpoint.tls && endpoint.port == 443) || (!endpoint.tls && endpoint.port == 80) {
                endpoint.host.clone()
            } else {
                format!("{}:{}", endpoint.host, endpoint.port)
            };
        let target = format!("TrentService.{action}");
        let mut headers = vec![
            ("content-type", "application/x-amz-json-1.1"),
            ("host", host.as_str()),
            ("x-amz-date", date.as_str()),
        ];
        if let Some(token) = &credentials.session_token {
            headers.push(("x-amz-security-token", token.as_str()));
        }
        headers.push(("x-amz-target", target.as_str()));
        let authorization = sigv4_authorization(
            "POST",
            "/",
            &headers,
            &body,
            &self.region,
            "kms",
            &date,
            &credentials.access_key,
            &credentials.secret_key,
        )?;
        let mut request = String::from("POST / HTTP/1.1\r\n");
        for (name, value) in &headers {
            request.push_str(&format!("{name}: {value}\r\n"));
        }
        request.push_str(&format!(
            "authorization: {authorization}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
            body.len()
        ));
        let mut wire = Zeroizing::new(request.into_bytes());
        wire.extend_from_slice(&body);
        let (status, response) = parse_response(&transport(&endpoint, &wire)?)?;
        if status != 200 {
            return Err(kms_error(status, &response));
        }
        Ok(serde_json::from_slice(&response)?)
    }

    /// Fetch a key's public point and require the expected spec and usage.
    fn public_point(&self, arn: &str, usage: &str) -> Result<Vec<u8>> {
        let response = self.call("GetPublicKey", json!({"KeyId": arn}))?;
        if response["KeySpec"] != "ECC_NIST_P384" {
            return Err(Error::new(
                "mechanism_unsupported",
                "KMS key is not ECC_NIST_P384",
            ));
        }
        if response["KeyUsage"] != usage {
            return Err(Error::new(
                "policy_mismatch",
                format!("KMS key usage must be {usage}"),
            ));
        }
        let spki = unbase64(response["PublicKey"].as_str().unwrap_or(""))?;
        let point = spki
            .strip_prefix(&P384_SPKI_PREFIX[..])
            .ok_or_else(|| Error::new("provider_error", "Unexpected KMS public key encoding"))?;
        crypto::p384_point(point)?;
        Ok(point.to_vec())
    }
}

/// DER SubjectPublicKeyInfo prefix for an ML-DSA-65 key (id-ml-dsa-65,
/// 2.16.840.1.101.3.4.3.18, no parameters) followed by the 1952-byte key.
const MLDSA65_SPKI_PREFIX: [u8; 22] = [
    0x30, 0x82, 0x07, 0xb2, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03,
    0x12, 0x03, 0x82, 0x07, 0xa1, 0x00,
];
const MLDSA65_PUBLIC_KEY_LEN: usize = 1952;
const MLDSA65_SIGNATURE_LEN: usize = 3309;

impl Client {
    /// Fetch an ML_DSA_65 SIGN_VERIFY key's raw public key.
    fn mldsa_public_key(&self, arn: &str) -> Result<Vec<u8>> {
        let response = self.call("GetPublicKey", json!({"KeyId": arn}))?;
        if response["KeySpec"] != "ML_DSA_65" {
            return Err(Error::new(
                "mechanism_unsupported",
                "KMS key is not ML_DSA_65",
            ));
        }
        if response["KeyUsage"] != "SIGN_VERIFY" {
            return Err(Error::new(
                "policy_mismatch",
                "KMS key usage must be SIGN_VERIFY",
            ));
        }
        let spki = unbase64(response["PublicKey"].as_str().unwrap_or(""))?;
        let key = spki
            .strip_prefix(&MLDSA65_SPKI_PREFIX[..])
            .filter(|key| key.len() == MLDSA65_PUBLIC_KEY_LEN)
            .ok_or_else(|| Error::new("provider_error", "Unexpected KMS ML-DSA key encoding"))?;
        Ok(key.to_vec())
    }
}

/// Decode a DER ECDSA signature into fixed-width 48-byte r || s.
fn der_signature(der: &[u8]) -> Result<Vec<u8>> {
    let invalid = || Error::new("provider_error", "Malformed ECDSA signature from KMS");
    let integer = |input: &[u8]| -> Result<(Vec<u8>, usize)> {
        let (&tag, rest) = input.split_first().ok_or_else(invalid)?;
        let (&length, rest) = rest.split_first().ok_or_else(invalid)?;
        let length = usize::from(length);
        if tag != 0x02 || length == 0 || length > 49 || rest.len() < length {
            return Err(invalid());
        }
        let value = &rest[..length];
        let trimmed = if value.len() == 49 && value[0] == 0 {
            &value[1..]
        } else {
            value
        };
        if trimmed.len() > 48 {
            return Err(invalid());
        }
        let mut out = vec![0; 48 - trimmed.len()];
        out.extend_from_slice(trimmed);
        Ok((out, 2 + length))
    };
    let body = match der {
        [0x30, length, body @ ..] if usize::from(*length) == body.len() => body,
        [0x30, 0x81, length, body @ ..] if usize::from(*length) == body.len() => body,
        _ => return Err(invalid()),
    };
    let (r, used) = integer(body)?;
    let (s, rest) = integer(&body[used..])?;
    if used + rest != body.len() {
        return Err(invalid());
    }
    Ok([r, s].concat())
}

pub struct KmsIdentity {
    public: PublicKey,
    client: Client,
    encryption_key: String,
    signing_key: String,
    /// ML-DSA key ARN and raw public key, for composite signatures.
    mldsa: Option<(String, Vec<u8>)>,
}
impl IdentityKey for KmsIdentity {
    fn public(&self) -> &PublicKey {
        &self.public
    }
    fn custody(&self) -> Custody {
        Custody::Service
    }
    fn sign_raw(&self, message: &[u8]) -> Result<Vec<u8>> {
        let response = self.client.call(
            "Sign",
            json!({"KeyId": self.signing_key, "Message": base64(&crypto::p384_digest(message)),
                "MessageType": "DIGEST", "SigningAlgorithm": "ECDSA_SHA_384"}),
        )?;
        let mut signature =
            der_signature(&unbase64(response["Signature"].as_str().unwrap_or(""))?)?;
        if let Some((arn, public_key)) = &self.mldsa {
            // KMS signs the FIPS 204 message representative (external mu), which
            // carries IPG's context; the result is a pure ML-DSA signature over the
            // framed message.
            let mu = crypto::mldsa_mu(public_key, crypto::P384_MLDSA_CONTEXT, message)?;
            let response = self.client.call(
                "Sign",
                json!({"KeyId": arn, "Message": base64(&mu), "MessageType": "EXTERNAL_MU",
                    "SigningAlgorithm": "ML_DSA_SHAKE_256"}),
            )?;
            let pq = unbase64(response["Signature"].as_str().unwrap_or(""))?;
            if pq.len() != MLDSA65_SIGNATURE_LEN {
                return Err(Error::new(
                    "provider_error",
                    "KMS returned an unexpected ML-DSA signature length",
                ));
            }
            signature.extend_from_slice(&pq);
        }
        Ok(signature)
    }
    fn agree(&self, peer: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        crypto::p384_point(peer)?;
        let spki = [&P384_SPKI_PREFIX[..], peer].concat();
        let response = self.client.call(
            "DeriveSharedSecret",
            json!({"KeyId": self.encryption_key, "KeyAgreementAlgorithm": "ECDH", "PublicKey": base64(&spki)}),
        )?;
        let shared = Zeroizing::new(unbase64(response["SharedSecret"].as_str().unwrap_or(""))?);
        if shared.len() != 48 {
            return Err(Error::new(
                "provider_error",
                "KMS returned an unexpected shared secret length",
            ));
        }
        Ok(shared)
    }
}

fn identity(
    region: &str,
    encryption_key: &str,
    signing_key: &str,
    mldsa_key: Option<&str>,
) -> Result<KmsIdentity> {
    provider::check_kms_keys(region, encryption_key, signing_key, mldsa_key)?;
    let client = Client {
        region: region.into(),
        partition: provider::parse_arn(encryption_key)?.partition,
    };
    let encryption = client.public_point(encryption_key, "KEY_AGREEMENT")?;
    let mut signing = client.public_point(signing_key, "SIGN_VERIFY")?;
    let mldsa = mldsa_key
        .map(|arn| Ok::<_, Error>((arn.to_string(), client.mldsa_public_key(arn)?)))
        .transpose()?;
    let suite = match &mldsa {
        Some((_, public_key)) => {
            signing.extend_from_slice(public_key);
            Suite::P384MlDsa
        }
        None => Suite::P384,
    };
    Ok(KmsIdentity {
        public: crypto::identity(suite, &encryption, &signing)?,
        client,
        encryption_key: encryption_key.into(),
        signing_key: signing_key.into(),
        mldsa,
    })
}

pub fn open(key: &KmsKey) -> Result<Box<dyn IdentityKey>> {
    let identity = identity(
        &key.region,
        &key.encryption_key_arn,
        &key.signing_key_arn,
        key.mldsa_signing_key_arn.as_deref(),
    )?;
    if identity.public != key.public {
        return Err(Error::new(
            "identity_mismatch",
            "KMS public keys do not match the pinned identity",
        ));
    }
    Ok(Box::new(identity))
}

pub fn bind(
    region: &str,
    encryption_key_arn: &str,
    signing_key_arn: &str,
    mldsa_signing_key_arn: Option<&str>,
) -> Result<(KmsKey, Protection)> {
    let identity = identity(
        region,
        encryption_key_arn,
        signing_key_arn,
        mldsa_signing_key_arn,
    )?;
    // GetPublicKey does not report key origin, so no generation claim is made.
    let protection = provider::prove_possession(&identity, false)?;
    let key = KmsKey {
        format: provider::KMS_KEY_FORMAT.into(),
        public: identity.public.clone(),
        region: region.into(),
        encryption_key_arn: encryption_key_arn.into(),
        signing_key_arn: signing_key_arn.into(),
        mldsa_signing_key_arn: mldsa_signing_key_arn.map(Into::into),
    };
    key.validate()?;
    Ok((key, protection))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sigv4_matches_the_published_get_vanilla_vector() {
        // AWS Signature Version 4 test suite, "get-vanilla".
        let authorization = sigv4_authorization(
            "GET",
            "/",
            &[
                ("host", "example.amazonaws.com"),
                ("x-amz-date", "20150830T123600Z"),
            ],
            b"",
            "us-east-1",
            "service",
            "20150830T123600Z",
            "AKIDEXAMPLE",
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        )
        .unwrap();
        assert_eq!(
            authorization,
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
        );
    }

    #[test]
    fn dates_encodings_and_arns() {
        assert_eq!(amz_date(0), "19700101T000000Z");
        assert_eq!(amz_date(1_440_938_160), "20150830T123600Z");
        assert_eq!(amz_date(951_782_400), "20000229T000000Z");
        for data in [&b""[..], b"f", b"fo", b"foo", b"foob", b"fooba", b"foobar"] {
            assert_eq!(unbase64(&base64(data)).unwrap(), data);
        }
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
        assert_eq!(base64(b"fo"), "Zm8=");
        let parse = provider::parse_arn;
        assert!(
            parse("arn:aws:kms:us-east-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab")
                .is_ok()
        );
        assert!(parse("arn:aws:kms:us-east-1:123456789012:alias/name").is_err());
        assert!(parse("arn:aws:s3:us-east-1:123456789012:key/x").is_err());
        assert!(parse("arn:aws:kms:us-east-1:12345:key/1234").is_err());
    }

    #[test]
    fn der_signatures_decode_to_fixed_width() {
        let mut der = vec![0x30, 0x65, 0x02, 0x31, 0x00];
        der.extend([0xff; 48]);
        der.extend([0x02, 0x30]);
        der.extend([0x01; 48]);
        let raw = der_signature(&der).unwrap();
        assert_eq!(&raw[..48], &[0xff; 48]);
        assert_eq!(&raw[48..], &[0x01; 48]);
        let short = [0x30, 0x06, 0x02, 0x01, 0x05, 0x02, 0x01, 0x07];
        let raw = der_signature(&short).unwrap();
        assert_eq!((raw[47], raw[95]), (5, 7));
        assert!(der_signature(&[0x30, 0x03, 0x02, 0x01, 0x05]).is_err());
    }

    #[test]
    fn rfc3339_times_and_ini_sections() {
        assert_eq!(unix_time("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(unix_time("2015-08-30T12:36:00Z"), Some(1_440_938_160));
        assert_eq!(unix_time("2000-02-29T00:00:00.123Z"), Some(951_782_400));
        assert_eq!(
            unix_time("2026-09-28T20:00:00UTC"),
            unix_time("2026-09-28T20:00:00Z")
        );
        assert!(unix_time("2026-13-01T00:00:00Z").is_none());
        assert!(unix_time("2026-09-28T20:00:00+02:00").is_none());
        let ini = "[default]\nregion = x\n[profile  dev]\nsso_session = corp\n[sso-session corp]\nsso_region = us-east-1\n";
        assert_eq!(
            ini_section(ini, "profile dev").unwrap()["sso_session"],
            "corp"
        );
        assert_eq!(
            ini_section(ini, "sso-session corp").unwrap()["sso_region"],
            "us-east-1"
        );
        assert!(ini_section(ini, "profile missing").is_none());
    }

    #[test]
    fn sts_encoding_and_xml() {
        assert_eq!(form("a b/c+d=e"), "a%20b%2Fc%2Bd%3De");
        let xml =
            "<R><AccessKeyId>ASIA1</AccessKeyId><SecretAccessKey>s&amp;/+</SecretAccessKey></R>";
        assert_eq!(xml_text(xml, "AccessKeyId").unwrap(), "ASIA1");
        assert_eq!(xml_text(xml, "SecretAccessKey").unwrap(), "s&/+");
        assert!(xml_text(xml, "SessionToken").is_none());
    }

    #[test]
    fn chunked_and_plain_responses_parse() {
        let plain = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}";
        assert_eq!(parse_response(plain).unwrap(), (200, b"{}".to_vec()));
        let chunked = b"HTTP/1.1 400 Bad\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n";
        assert_eq!(parse_response(chunked).unwrap(), (400, b"{}".to_vec()));
        assert!(parse_response(b"garbage").is_err());
    }
}
