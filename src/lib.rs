//! Let's Encrypt SSL support for Actix web applications using acme-client
//!
//! # Proof-of-concept
//!
//! The code in this repository has been lightly tested, but I am
//! unhappy with the API I've constructed.  I especially dislike the
//! split between the app_encryption_enabler and the
//! server_encryption_enabler.  I'm new to Rust and wanted to write
//! *something* and then ask for suggestions for a better API.
//!
//! I haven't yet written documentation for the public functions because
//! I think it's likely they'll change.  However, if the example below isn't
//! sufficient to illustrate the sort of behavior I'm trying to make available
//! I can go ahead and document what is present.
//!
//! This version only works with openssl.
//!
//! ```rust
//! // Although the following code doesn't run as-is, it's basically a
//! // simplified version of code that has run.  Unfortunately, there's no
//! // way to provide a sample that will run 100% out of the box, because
//! // to use a certificate you must have DNS pointing a domain to the host
//! // you're running this on.
//! #![feature(proc_macro_hygiene)]
//! 
//! use {
//!     actix_web::{
//!         actix::Actor, http::Method, server, App,
//!         HttpRequest, HttpResponse, Result,
//!     },
//!     actix_web_lets_encrypt::{CertBuilder, LetsEncrypt},
//! };
//! 
//! // ... asset and other non-certificate code elided ...
//! 
//! fn main() {
//!     let example_prod = CertBuilder::new("0.0.0.0:8089", &["example.com"]).email("ctm@example.com");
//! 
//!     let two_certs_prod =
//!         CertBuilder::new("0.0.0.0:8090", &["example.org", "example.net"]).email("ctm@example.org");
//! 
//!     let example_test = CertBuilder::new("0.0.0.0:8091", &["test.example.com"])
//!         .email("ctm@example.com")
//!         .test();
//! 
//!     // 8088 is for all http and is bound after we set up the server.
//!     let app_encryption_enabler = LetsEncrypt::encryption_enabler()
//!         .nonce_directory("/var/nonce")
//!         .ssl_directory("ssl")
//!         .add_cert(example_prod)
//!         .add_cert(two_certs_prod)
//!         .add_cert(example_test);
//! 
//!     let server_encryption_enabler = app_encryption_enabler.clone();
//! 
//!     let mut server = server::new(move || {
//!         App::new().configure(|app| {
//!             let app = app
//!                 .resource("/assets/{asset:.*}", |r| r.method(Method::GET).f(asset))
//!                 .resource("/", |r| r.method(Method::GET).f(index));
//!             app_encryption_enabler.register(app)
//!         })
//!     });
//! 
//!     server = server_encryption_enabler
//!                  .attach_certificates_to(server)
//!                  .bind("0.0.0.0:8088")
//!                  .unwrap()
//!     };
//!     server_encryption_enabler.start();
//!     server.run();
//! }
//! ```

use {
    acme_client::{error::Error, Directory},
    actix::prelude::*,
    actix_web::{
        self,
        fs::NamedFile,
        http::Method,
        server::{HttpServer, IntoHttpHandler},
        App, HttpRequest,
    },
    chrono::{offset::TimeZone, Duration, Utc},
    openssl::{
        ssl::{SslAcceptor, SslAcceptorBuilder, SslFiletype, SslMethod},
        x509::X509,
    },
    std::{
        fs::{self, File},
        io::Read,
        net::{SocketAddr, ToSocketAddrs},
        path::{Path, PathBuf},
        str::FromStr,
    },
};

#[derive(Clone)]
pub struct CertBuilder {
    addrs: Vec<SocketAddr>,
    domains: Vec<String>,
    email: Option<String>,
    production: bool,
    renew_within: Duration,
    check_every: std::time::Duration,
    key_path: Option<PathBuf>,
    cert_path: Option<PathBuf>,
}

impl CertBuilder {
    pub fn new<S, D>(addrs: S, domains: &[D]) -> Self
    where
        S: ToSocketAddrs,
        D: AsRef<str>,
    {
        let addrs = addrs.to_socket_addrs().unwrap().collect();
        let domains = domains.iter().map(|d| d.as_ref().to_string()).collect();
        let renew_within = Duration::days(30);
        let check_every = Duration::hours(12).to_std().unwrap();

        CertBuilder {
            addrs,
            domains,
            email: None,
            production: true,
            renew_within,
            check_every,
            key_path: None,
            cert_path: None,
        }
    }

    pub fn email<E: AsRef<str>>(mut self, email: E) -> Self {
        self.email = Some(email.as_ref().to_string());
        self
    }

    pub fn test(mut self) -> Self {
        self.production = false;
        self
    }

    pub fn renew_within(mut self, renewal: &Duration) -> Self {
        self.renew_within = *renewal;
        self
    }

    pub fn check_every(mut self, period: &Duration) -> Self {
        self.check_every = period.to_std().unwrap();
        self
    }

    fn key_and_cert_present(&self) -> bool {
        let key_path = self.key_path.as_ref().unwrap();
        let cert_path = self.cert_path.as_ref().unwrap();

        fs::metadata(key_path).is_ok() && fs::metadata(cert_path).is_ok()
    }

    fn ssl_builder(&self) -> SslAcceptorBuilder {
        let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
        builder
            .set_private_key_file(self.key_path.clone().unwrap(), SslFiletype::PEM)
            .unwrap();
        builder
            .set_certificate_chain_file(self.cert_path.clone().unwrap())
            .unwrap();
        builder
    }

    fn update_key_path(&mut self, ssl_directory: &PathBuf) {
        Self::update_path(&mut self.key_path, "key", ssl_directory, &self.domains);
    }

    fn update_cert_path(&mut self, ssl_directory: &PathBuf) {
        Self::update_path(&mut self.cert_path, "cert", ssl_directory, &self.domains);
    }

    fn update_path(
        pathp: &mut Option<PathBuf>,
        stem: &str,
        ssl_directory: &PathBuf,
        domains: &[String],
    ) {
        let mut file;

        match pathp {
            None => file = Self::default_file(stem, domains),
            Some(path) => {
                if path.is_absolute() {
                    *pathp = Some(path.to_path_buf());
                    return;
                } else {
                    file = path.to_path_buf();
                }
            }
        }
        *pathp = Some(ssl_directory.join(file));
    }

    fn default_file(stem: &str, domains: &[String]) -> PathBuf {
        PathBuf::from_str(&format!("{}_{}.pem", &domains[0], stem)).unwrap()
    }

    fn needs_building(&self) -> bool {
        if !self.key_and_cert_present() {
            return true;
        }
        let path = self.cert_path.as_ref().unwrap();

        let mut f = File::open(path).unwrap();
        let mut cert = Vec::new();
        f.read_to_end(&mut cert).unwrap();
        let cert = X509::from_pem(&cert).ok().unwrap();
        let not_after = cert.not_after().to_string();
        let not_after = Utc
            .datetime_from_str(&not_after, "%b %d %H:%M:%S %Y GMT")
            .unwrap();
        let time_remaining = not_after.signed_duration_since(Utc::now());
        time_remaining < self.renew_within
    }
}

#[derive(Clone)]
pub struct LetsEncrypt {
    nonce_directory: PathBuf,
    ssl_directory: PathBuf,
    cert_builders: Vec<CertBuilder>,
}

impl LetsEncrypt {
    pub fn encryption_enabler() -> Self {
        const DEFAULT_NONCE_DIRECTORY: &str = "/var/tmp/lets_encrypt";
        const DEFAULT_SSL_DIRECTORY: &str = "/ssl";

        Self {
            nonce_directory: PathBuf::from(DEFAULT_NONCE_DIRECTORY),
            ssl_directory: PathBuf::from(DEFAULT_SSL_DIRECTORY),
            cert_builders: Vec::new(),
        }
    }

    pub fn nonce_directory<P>(mut self, path: P) -> Self
    where
        P: AsRef<Path>,
    {
        self.nonce_directory = PathBuf::from(path.as_ref());
        self
    }

    pub fn add_cert(mut self, mut cert: CertBuilder) -> Self {
        cert.update_key_path(&self.ssl_directory);
        cert.update_cert_path(&self.ssl_directory);
        self.cert_builders.push(cert);
        self
    }

    pub fn ssl_directory<P>(mut self, path: P) -> Self
    where
        P: AsRef<Path>,
    {
        self.ssl_directory = PathBuf::from(path.as_ref());
        self
    }

    pub fn register(&self, app: App) -> App {
        let nonce = self.nonce();

        app.resource("/.well-known/acme-challenge/{token}", |r| {
            r.method(Method::GET).f(nonce)
        })
    }

    pub fn attach_certificates_to<H, F>(&self, mut server: HttpServer<H, F>) -> HttpServer<H, F>
    where
        H: IntoHttpHandler + 'static,
        F: Fn() -> H + Send + Clone + 'static,
    {
        for cert_builder in &self.cert_builders {
            if cert_builder.key_and_cert_present() {
                server = server
                    .bind_ssl(&cert_builder.addrs[..], cert_builder.ssl_builder())
                    .unwrap();
            }
        }
        server
    }

    fn nonce(&self) -> impl Fn(&HttpRequest) -> actix_web::Result<NamedFile> {
        let path = PathBuf::from(&self.nonce_directory);

        move |req: &HttpRequest| {
            let token: PathBuf = req.match_info().query("token")?;
            let path = PathBuf::from(&path)
                .join(".well-known")
                .join("acme-challenge")
                .join(token);
            Ok(NamedFile::open(path)?)
        }
    }

    fn build_cert(&self, cert_builder: &CertBuilder) -> Result<(), Error> {
        let directory = if cert_builder.production {
            Directory::lets_encrypt()
        } else {
            Directory::from_url("https://acme-staging.api.letsencrypt.org/directory")
        }?;
        let mut account = directory.account_registration();
        if let Some(email) = &cert_builder.email {
            account = account.email(email);
        }
        let account = account.register()?;

        for domain in &cert_builder.domains {
            let authorization = account.authorization(&domain)?;
            let http_challenge = authorization
                .get_http_challenge()
                .ok_or("HTTP challenge not found")?;
            http_challenge.save_key_authorization(self.nonce_directory.clone())?;
            http_challenge.validate()?;
        }
        let domains: Vec<&str> = cert_builder.domains.iter().map(|d| &d[..]).collect();
        let cert = account
            .certificate_signer(&domains[..])
            .sign_certificate()?;
        cert.save_signed_certificate(&cert_builder.cert_path.as_ref().unwrap())?;
        cert.save_private_key(&cert_builder.key_path.as_ref().unwrap())?;
        Ok(())
    }

    fn cert_built(&self, cert_builder: &CertBuilder) -> bool {
        if cert_builder.needs_building() {
            self.build_cert(cert_builder).expect("could create cert");
            true
        } else {
            false
        }
    }
}

impl Actor for LetsEncrypt {
    type Context = Context<LetsEncrypt>;

    fn started(&mut self, ctx: &mut Self::Context) {
        let mut needs_restart = false;
        for cert_builder in &self.cert_builders {
            needs_restart = needs_restart || self.cert_built(cert_builder);
        }
        if needs_restart {
            actix::System::current().stop();
        } else {
            for cert_builder in &self.cert_builders {
                let cert_builder = cert_builder.clone();
                ctx.run_interval(cert_builder.check_every, move |act, _ctx| {
                    if act.cert_built(&cert_builder) {
                        actix::System::current().stop();
                    }
                });
            }
        }
    }
}
