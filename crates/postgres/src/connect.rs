use crate::dsn::{self, ConnConfig, Roots, SessionAttrs, TlsPlan, Verify};
use crate::goerr::errno_text;
use postgres::config::{ChannelBinding, SslMode, SslNegotiation};
use postgres::{Client, NoTls};
use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{AlertDescription, CertificateError, ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use std::error::Error as StdError;
use std::net::{IpAddr, ToSocketAddrs};
use std::sync::Arc;

enum Addr {
    Tcp(IpAddr),
    Unix(String),
}

struct Attempt<'a> {
    addr: Addr,
    port: u16,
    address: String,
    original: &'a str,
    tls: Option<&'a Arc<TlsPlan>>,
}

struct Failure {
    text: String,
    code: Option<String>,
    not_preferred: bool,
}

impl Failure {
    fn plain(text: impl Into<String>) -> Self {
        Failure { text: text.into(), code: None, not_preferred: false }
    }
}

#[derive(Debug)]
struct NoVerify(Arc<CryptoProvider>);

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn verify_tls13_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

#[derive(Debug)]
struct ChainOnly(Arc<WebPkiServerVerifier>);

impl ServerCertVerifier for ChainOnly {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        match self.0.verify_server_cert(end_entity, intermediates, server_name, ocsp, now) {
            Err(rustls::Error::InvalidCertificate(CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. })) => {
                Ok(ServerCertVerified::assertion())
            }
            other => other,
        }
    }

    fn verify_tls12_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.0.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.0.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.supported_verify_schemes()
    }
}

#[derive(Debug)]
struct NameFirst(Arc<WebPkiServerVerifier>);

impl ServerCertVerifier for NameFirst {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let cert = webpki::EndEntityCert::try_from(end_entity).map_err(|_| rustls::Error::InvalidCertificate(CertificateError::BadEncoding))?;
        if let Err(webpki::Error::CertNotValidForName(ctx)) = cert.verify_is_valid_for_subject_name(server_name) {
            return Err(rustls::Error::InvalidCertificate(CertificateError::NotValidForNameContext { expected: ctx.expected, presented: ctx.presented }));
        }
        self.0.verify_server_cert(end_entity, intermediates, server_name, ocsp, now)
    }

    fn verify_tls12_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.0.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.0.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.supported_verify_schemes()
    }
}

fn webpki_verifier(roots: &Roots, provider: &Arc<CryptoProvider>) -> Result<Arc<WebPkiServerVerifier>, String> {
    let mut store = RootCertStore::empty();
    match roots {
        Roots::Pem(certs) => {
            store.add_parsable_certificates(certs.iter().cloned());
        }
        Roots::System => {
            store.add_parsable_certificates(rustls_native_certs::load_native_certs().certs);
        }
    }
    WebPkiServerVerifier::builder_with_provider(Arc::new(store), provider.clone())
        .build()
        .map_err(|_| "tls: failed to verify certificate: x509: failed to load system roots and no roots provided".to_string())
}

fn rustls_config(plan: &TlsPlan) -> Result<ClientConfig, String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier: Arc<dyn ServerCertVerifier> = match plan.verify {
        Verify::None => Arc::new(NoVerify(provider.clone())),
        Verify::Chain => Arc::new(ChainOnly(webpki_verifier(&plan.roots, &provider)?)),
        Verify::Full => Arc::new(NameFirst(webpki_verifier(&plan.roots, &provider)?)),
    };
    let builder = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("tls: {e}"))?
        .dangerous()
        .with_custom_certificate_verifier(verifier);
    let mut cfg = match &plan.client {
        Some((certs, key)) => builder.with_client_auth_cert(certs.clone(), key.clone_key()).map_err(|e| format!("tls: {e}"))?,
        None => builder.with_no_client_auth(),
    };
    cfg.enable_sni = plan.sni;
    if plan.direct {
        cfg.alpn_protocols = vec![b"postgresql".to_vec()];
    }
    Ok(cfg)
}

fn alert_text(a: &AlertDescription) -> String {
    use AlertDescription as A;
    match a {
        A::CloseNotify => "close notify".into(),
        A::UnexpectedMessage => "unexpected message".into(),
        A::BadRecordMac => "bad record MAC".into(),
        A::DecryptionFailed => "decryption failed".into(),
        A::RecordOverflow => "record overflow".into(),
        A::DecompressionFailure => "decompression failure".into(),
        A::HandshakeFailure => "handshake failure".into(),
        A::BadCertificate => "bad certificate".into(),
        A::UnsupportedCertificate => "unsupported certificate".into(),
        A::CertificateRevoked => "revoked certificate".into(),
        A::CertificateExpired => "expired certificate".into(),
        A::CertificateUnknown => "unknown certificate".into(),
        A::IllegalParameter => "illegal parameter".into(),
        A::UnknownCA => "unknown certificate authority".into(),
        A::AccessDenied => "access denied".into(),
        A::DecodeError => "error decoding message".into(),
        A::DecryptError => "error decrypting message".into(),
        A::ExportRestriction => "export restriction".into(),
        A::ProtocolVersion => "protocol version not supported".into(),
        A::InsufficientSecurity => "insufficient security level".into(),
        A::InternalError => "internal error".into(),
        A::InappropriateFallback => "inappropriate fallback".into(),
        A::UserCanceled => "user canceled".into(),
        A::NoRenegotiation => "no renegotiation".into(),
        A::MissingExtension => "missing extension".into(),
        A::UnsupportedExtension => "unsupported extension".into(),
        A::CertificateUnobtainable => "certificate unobtainable".into(),
        A::UnrecognisedName => "unrecognized name".into(),
        A::BadCertificateStatusResponse => "bad certificate status response".into(),
        A::BadCertificateHashValue => "bad certificate hash value".into(),
        A::UnknownPSKIdentity => "unknown PSK identity".into(),
        A::CertificateRequired => "certificate required".into(),
        A::NoApplicationProtocol => "no application protocol".into(),
        A::EncryptedClientHelloRequired => "encrypted client hello required".into(),
        other => format!("alert({})", u8::from(*other)),
    }
}

fn hostname_error(host: &str, presented: &[String]) -> String {
    let inner = |p: &str, pre: &str, post: &str| p.strip_prefix(pre).and_then(|r| r.strip_suffix(post)).map(str::to_string);
    let dns: Vec<String> = presented.iter().filter_map(|p| inner(p, "DnsName(\"", "\")")).collect();
    let ips: Vec<String> = presented.iter().filter_map(|p| inner(p, "IpAddress(", ")")).collect();
    if host.parse::<IpAddr>().is_ok() {
        if ips.is_empty() {
            return format!("x509: cannot validate certificate for {host} because it doesn't contain any IP SANs");
        }
        return format!("x509: certificate is valid for {}, not {host}", ips.join(", "));
    }
    if dns.is_empty() {
        return format!("x509: certificate is not valid for any names, but wanted to match {host}");
    }
    format!("x509: certificate is valid for {}, not {host}", dns.join(", "))
}

fn go_tls_error(e: &rustls::Error, verify: Verify, host: &str) -> String {
    match e {
        rustls::Error::InvalidCertificate(c) => {
            let body = match c {
                CertificateError::UnknownIssuer => "x509: certificate signed by unknown authority".to_string(),
                CertificateError::NotValidForName => hostname_error(host, &[]),
                CertificateError::NotValidForNameContext { presented, .. } => hostname_error(host, presented),
                CertificateError::Expired | CertificateError::ExpiredContext { .. } | CertificateError::NotValidYet | CertificateError::NotValidYetContext { .. } => {
                    "x509: certificate has expired or is not yet valid".to_string()
                }
                other => format!("x509: {other:?}"),
            };
            match verify {
                Verify::Chain => body,
                _ => format!("tls: failed to verify certificate: {body}"),
            }
        }
        rustls::Error::AlertReceived(a) => format!("remote error: tls: {}", alert_text(a)),
        other => format!("tls: {other}"),
    }
}

fn find_in_chain<'a, T: StdError + 'static>(e: &'a (dyn StdError + 'static)) -> Option<&'a T> {
    let mut cur: Option<&(dyn StdError + 'static)> = Some(e);
    while let Some(c) = cur {
        if let Some(t) = c.downcast_ref::<T>() {
            return Some(t);
        }
        if let Some(io) = c.downcast_ref::<std::io::Error>()
            && let Some(inner) = io.get_ref()
            && let Some(t) = inner.downcast_ref::<T>()
        {
            return Some(t);
        }
        cur = c.source();
    }
    None
}

fn chain_text(e: &(dyn StdError + 'static)) -> String {
    let mut out = e.to_string();
    let mut cur = e.source();
    while let Some(c) = cur {
        out.push_str(": ");
        out.push_str(&c.to_string());
        cur = c.source();
    }
    out
}

fn classify(e: &postgres::Error, a: &Attempt) -> Failure {
    if let Some(db) = e.as_db_error() {
        return Failure {
            text: format!("server error: {}: {} (SQLSTATE {})", db.severity(), db.message(), db.code().code()),
            code: Some(db.code().code().to_string()),
            not_preferred: false,
        };
    }
    let top = e.to_string();
    let source = e.source();
    if top.starts_with("error connecting to server") {
        let net = match a.addr {
            Addr::Tcp(_) => "tcp",
            Addr::Unix(_) => "unix",
        };
        return Failure::plain(match source.and_then(find_in_chain::<std::io::Error>) {
            Some(io) if io.kind() == std::io::ErrorKind::TimedOut && io.raw_os_error().is_none() => "dial error: timeout: context deadline exceeded".to_string(),
            Some(io) => format!("dial error: dial {net} {}: connect: {}", a.address, errno_text(io)),
            None => "dial error".to_string(),
        });
    }
    if top.starts_with("error performing TLS handshake") {
        if source.is_some_and(|s| s.to_string() == "server does not support TLS") {
            return Failure::plain("tls error: server refused TLS connection");
        }
        let verify = a.tls.map(|p| p.verify).unwrap_or(Verify::None);
        if let Some(r) = source.and_then(find_in_chain::<rustls::Error>) {
            return Failure::plain(format!("failed to write startup message: write failed: {}", go_tls_error(r, verify, a.original)));
        }
        return Failure::plain(format!("failed to write startup message: write failed: {}", source.map(chain_text).unwrap_or_default()));
    }
    Failure::plain(format!("failed to receive message: {}", chain_text(e)))
}

fn first_cell(client: &mut Client, sql: &str) -> Result<String, String> {
    for msg in client.simple_query(sql).map_err(|e| crate::query_error(&e))? {
        if let postgres::SimpleQueryMessage::Row(row) = msg {
            return Ok(row.get(0).unwrap_or("").to_string());
        }
    }
    Ok(String::new())
}

fn validate(client: &mut Client, attrs: SessionAttrs, ignore_not_preferred: bool) -> Result<(), Failure> {
    let fail = |m: String| Failure::plain(format!("ValidateConnect failed: {m}"));
    let check = |client: &mut Client, sql: &str| first_cell(client, sql).map_err(fail);
    match attrs {
        SessionAttrs::Any => Ok(()),
        SessionAttrs::ReadWrite => match check(client, "show transaction_read_only")?.as_str() {
            "on" => Err(fail("read only connection".into())),
            _ => Ok(()),
        },
        SessionAttrs::ReadOnly => match check(client, "show transaction_read_only")?.as_str() {
            "on" => Ok(()),
            _ => Err(fail("connection is not read only".into())),
        },
        SessionAttrs::Standby => match check(client, "select pg_is_in_recovery()")?.as_str() {
            "t" => Ok(()),
            _ => Err(fail("server is not in hot standby mode".into())),
        },
        SessionAttrs::Primary => match check(client, "select pg_is_in_recovery()")?.as_str() {
            "t" => Err(fail("server is in standby mode".into())),
            _ => Ok(()),
        },
        SessionAttrs::PreferStandby => match check(client, "select pg_is_in_recovery()")?.as_str() {
            "t" => Ok(()),
            _ if ignore_not_preferred => Ok(()),
            _ => {
                let mut f = fail("server is not in hot standby mode".into());
                f.not_preferred = true;
                Err(f)
            }
        },
    }
}

fn attempt(cfg: &ConnConfig, a: &Attempt, ignore_not_preferred: bool) -> Result<Client, Failure> {
    let mut pc = postgres::Config::new();
    pc.user(&cfg.user);
    pc.password(cfg.password.as_bytes());
    if !cfg.database.is_empty() {
        pc.dbname(&cfg.database);
    }
    let (options, app) = cfg.startup_options();
    if let Some(o) = &options {
        pc.options(o);
    }
    if let Some(n) = &app {
        pc.application_name(n);
    }
    match &a.addr {
        #[cfg(unix)]
        Addr::Unix(dir) => {
            pc.host_path(dir);
        }
        #[cfg(not(unix))]
        Addr::Unix(_) => {
            return Err(Failure::plain(format!("dial error: dial unix {}: connect: unix sockets are not supported on this platform", a.address)));
        }
        Addr::Tcp(ip) => {
            pc.host(a.original);
            pc.hostaddr(*ip);
        }
    }
    pc.port(a.port);
    if let Some(t) = cfg.connect_timeout
        && !t.is_zero()
    {
        pc.connect_timeout(t);
    }
    pc.channel_binding(match cfg.channel_binding {
        ChannelBinding::Require => ChannelBinding::Prefer,
        other => other,
    });
    let connected = match a.tls {
        None => {
            pc.ssl_mode(SslMode::Disable);
            pc.connect(NoTls)
        }
        Some(plan) => {
            pc.ssl_mode(SslMode::Require);
            if plan.direct {
                pc.ssl_negotiation(SslNegotiation::Direct);
            }
            let rc = rustls_config(plan).map_err(Failure::plain)?;
            pc.connect(tokio_postgres_rustls::MakeRustlsConnect::new(rc))
        }
    };
    let mut client = connected.map_err(|e| {
        let mut f = classify(&e, a);
        if f.code.as_deref() == Some("28P01") && auth_request_code(cfg, a) == Some(10) {
            f.text = f.text.replacen("server error: ", "failed SASL auth: ", 1);
        }
        f
    })?;
    if cfg.channel_binding == ChannelBinding::Require
        && a.tls.is_none()
        && first_cell(&mut client, "select system_user").is_ok_and(|u| u.starts_with("scram-sha-256:"))
    {
        return Err(Failure::plain("failed SASL auth: channel binding required but server does not support SCRAM-SHA-256-PLUS"));
    }
    if cfg.min_protocol != "3.0" {
        let v: i64 = first_cell(&mut client, "show server_version_num").ok().and_then(|s| s.parse().ok()).unwrap_or(0);
        if v < 180000 {
            return Err(Failure::plain("server protocol version too low: %!w(<nil>)"));
        }
    }
    validate(&mut client, cfg.session_attrs, ignore_not_preferred)?;
    Ok(client)
}

fn startup_packet(cfg: &ConnConfig) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&196608i32.to_be_bytes());
    let mut param = |k: &str, v: &str| {
        body.extend_from_slice(k.as_bytes());
        body.push(0);
        body.extend_from_slice(v.as_bytes());
        body.push(0);
    };
    param("user", &cfg.user);
    if !cfg.database.is_empty() {
        param("database", &cfg.database);
    }
    body.push(0);
    let mut out = ((body.len() + 4) as i32).to_be_bytes().to_vec();
    out.extend(body);
    out
}

fn read_auth_code(stream: &mut impl std::io::Read) -> Option<i32> {
    let mut head = [0u8; 9];
    stream.read_exact(&mut head).ok()?;
    if head[0] != b'R' {
        return None;
    }
    Some(i32::from_be_bytes([head[5], head[6], head[7], head[8]]))
}

fn auth_request_code(cfg: &ConnConfig, a: &Attempt) -> Option<i32> {
    use std::io::{Read, Write};
    let timeout = Some(std::time::Duration::from_secs(10));
    let startup = startup_packet(cfg);
    match (&a.addr, a.tls) {
        #[cfg(unix)]
        (Addr::Unix(dir), _) => {
            let mut s = std::os::unix::net::UnixStream::connect(dsn::unix_socket_address(dir, a.port)).ok()?;
            s.set_read_timeout(timeout).ok()?;
            s.write_all(&startup).ok()?;
            read_auth_code(&mut s)
        }
        #[cfg(not(unix))]
        (Addr::Unix(_), _) => None,
        (Addr::Tcp(ip), tls) => {
            let mut tcp = std::net::TcpStream::connect_timeout(&std::net::SocketAddr::new(*ip, a.port), timeout?).ok()?;
            tcp.set_read_timeout(timeout).ok()?;
            let Some(plan) = tls else {
                tcp.write_all(&startup).ok()?;
                return read_auth_code(&mut tcp);
            };
            if !plan.direct {
                tcp.write_all(&[0, 0, 0, 8, 4, 210, 22, 47]).ok()?;
                let mut answer = [0u8; 1];
                tcp.read_exact(&mut answer).ok()?;
                if answer[0] != b'S' {
                    return None;
                }
            }
            let name = ServerName::try_from(a.original.to_string()).ok()?;
            let conn = rustls::ClientConnection::new(Arc::new(rustls_config(plan).ok()?), name).ok()?;
            let mut tls_stream = rustls::StreamOwned::new(conn, tcp);
            tls_stream.write_all(&startup).ok()?;
            read_auth_code(&mut tls_stream)
        }
    }
}

fn lookup_host(host: &str) -> Result<Vec<IpAddr>, String> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![ip]);
    }
    let not_found = || format!("lookup {host}: no such host");
    let addrs = (host, 0).to_socket_addrs().map_err(|_| not_found())?;
    let mut ips: Vec<IpAddr> = Vec::new();
    for a in addrs {
        if !ips.contains(&a.ip()) {
            ips.push(a.ip());
        }
    }
    if ips.is_empty() { Err(not_found()) } else { Ok(ips) }
}

fn join_host_port(ip: IpAddr, port: u16) -> String {
    match ip {
        IpAddr::V4(v) => format!("{v}:{port}"),
        IpAddr::V6(v) => format!("[{v}]:{port}"),
    }
}

fn connect_error(cfg: &ConnConfig, details: &str) -> String {
    let prefix = format!("failed to connect to `user={} database={}`:", cfg.user, cfg.database);
    if details.contains('\n') { format!("{prefix}\n\t{}", details.replace('\n', "\n\t")) } else { format!("{prefix} {details}") }
}

pub fn connect(conn: &str) -> Result<Client, String> {
    let cfg = dsn::parse_config(conn).map_err(|e| e.to_string())?;
    let mut errors: Vec<String> = Vec::new();
    let mut attempts: Vec<Attempt> = Vec::new();
    for fb in &cfg.fallbacks {
        if dsn::is_absolute_path(&fb.host) {
            attempts.push(Attempt {
                addr: Addr::Unix(fb.host.clone()),
                port: fb.port,
                address: dsn::unix_socket_address(&fb.host, fb.port),
                original: &fb.host,
                tls: fb.tls.as_ref(),
            });
            continue;
        }
        match lookup_host(&fb.host) {
            Ok(ips) => {
                for ip in ips {
                    attempts.push(Attempt { addr: Addr::Tcp(ip), port: fb.port, address: join_host_port(ip, fb.port), original: &fb.host, tls: fb.tls.as_ref() });
                }
            }
            Err(e) => errors.push(e),
        }
    }
    if attempts.is_empty() {
        return Err(connect_error(&cfg, &format!("hostname resolving error: {}", errors.join("\n"))));
    }
    let mut not_preferred: Option<&Attempt> = None;
    for a in &attempts {
        match attempt(&cfg, a, false) {
            Ok(c) => return Ok(c),
            Err(f) => {
                errors.push(format!("{} ({}): {}", a.address, a.original, f.text));
                if matches!(f.code.as_deref(), Some("28P01" | "3D000" | "42501")) {
                    return Err(connect_error(&cfg, &errors.join("\n")));
                }
                if f.not_preferred {
                    not_preferred = Some(a);
                }
            }
        }
    }
    if let Some(a) = not_preferred {
        match attempt(&cfg, a, true) {
            Ok(c) => return Ok(c),
            Err(f) => errors.push(format!("{} ({}): {}", a.address, a.original, f.text)),
        }
    }
    Err(connect_error(&cfg, &errors.join("\n")))
}
