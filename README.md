# actix-web-lets-encrypt

This software makes it fairly easy to use Lets Encrypt with Actix web.

## Proof-of-concept

The code in this repository has been lightly tested, but I am
unhappy with the API I've constructed.  I especially dislike the
split between the app_encryption_enabler and the
server_encryption_enabler.  I'm new to Rust and wanted to write
*something* and then ask for suggestions for a better API.

I haven't yet written documentation for the public functions because
I think it's likely they'll change.  However, if the example below isn't
sufficient to illustrate the sort of behavior I'm trying to make available
I can go ahead and document what is present.

This version only works with openssl.

```rust
// Although the following code doesn't run as-is, it's basically a
// simplified version of code that has run.  Unfortunately, there's no
// way to provide a sample that will run 100% out of the box, because
// to use a certificate you must have DNS pointing a domain to the host
// you're running this on.
#![feature(proc_macro_hygiene)]

use {
    actix_web::{
        actix::Actor, http::Method, server, App,
        HttpRequest, HttpResponse, Result,
    },
    actix_web_lets_encrypt::{CertBuilder, LetsEncrypt},
};

// ... asset and other non-certificate code elided ...

fn main() {
    let example_prod = CertBuilder::new("0.0.0.0:8089", &["example.com"]).email("ctm@example.com");

    let two_certs_prod =
        CertBuilder::new("0.0.0.0:8090", &["example.org", "example.net"]).email("ctm@example.org");

    let example_test = CertBuilder::new("0.0.0.0:8091", &["test.example.com"])
        .email("ctm@example.com")
        .test();

    // 8088 is for all http and is bound after we set up the server.
    let app_encryption_enabler = LetsEncrypt::encryption_enabler()
        .nonce_directory("/var/nonce")
        .ssl_directory("ssl")
        .add_cert(example_prod)
        .add_cert(two_certs_prod)
        .add_cert(example_test);

    let server_encryption_enabler = app_encryption_enabler.clone();

    let mut server = server::new(move || {
        App::new().configure(|app| {
            let app = app
                .resource("/assets/{asset:.*}", |r| r.method(Method::GET).f(asset))
                .resource("/", |r| r.method(Method::GET).f(index));
            app_encryption_enabler.register(app)
        })
    });

    server = server_encryption_enabler
                 .attach_certificates_to(server)
                 .bind("0.0.0.0:8088")
                 .unwrap()
    };
    server_encryption_enabler.start();
    server.run();
}
```

