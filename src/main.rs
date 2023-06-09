use std::collections::HashMap;
use std::fmt::format;
use std::net::ToSocketAddrs;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::Resolver;
use trust_dns_resolver::TokioAsyncResolver;

use tokio::io::{self, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{self, TcpListener, TcpStream};

async fn handle_connection(mut stream: TcpStream) -> Result<(), Box<dyn std::error::Error>> {
    let mut http_data = Vec::new();
    let mut buffer = [0u8; 1024];

    loop {
        let n = stream.read(&mut buffer).await?;
        println!("read {} bytes", n);
        http_data.extend_from_slice(&buffer[..n]);

        if n == 0 || n < 1024 {
            break;
        }
    }

    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut req = httparse::Request::new(&mut headers);
    let body_index = req.parse(&http_data)?.unwrap();
    let body = &http_data[body_index..];
    let method = req.method.unwrap();
    let path = req.path.unwrap();
    let version = req.version.unwrap();

    println!("method: {}", method);
    println!("path: {}", path);
    println!("version: {:?}", version);

    req.headers
        .iter()
        .for_each(|h| println!("{}: {}", h.name, String::from_utf8_lossy(h.value)));

    println!("{}", String::from_utf8_lossy(body));

    if path.to_lowercase().contains("monitorando") {
        let body_response = r#" <html>
                    <head>
                        <title>Exemplo de resposta HTTP </title>
                    </head>
                        <body>
                        Acesso não autorizado!
                        </body>
                </html>"#;

        // respond http request
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/html\r\n\r\n",
            body_response.len(),
        );

        stream.write_all(response.as_bytes()).await?;
        stream.write_all(body_response.as_bytes()).await?;
        stream.flush().await?;
    } else {
        // let response = format!("HTTP/1.1 200 OK\r\n\r\n");
        // stream.write_all(response.as_bytes()).await?;

        // connect to the hos in the host headers
        let mut host = String::new();
        for h in req.headers.iter() {
            if h.name.to_lowercase() == "host" {
                host = String::from_utf8_lossy(h.value).to_string();
                host.push('.');
                break;
            }
        }
        println!("host: {}", host);
        let resolver =
            TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default()).unwrap();
        let ips = resolver.lookup_ip(&host).await?;
        println!("ips: {:?}", ips);
        let ip = ips.iter().next().unwrap();

        println!("ip: {}", ip.to_string());
        let host_address = format!("{}:80", host);
        let mut host_stream = TcpStream::connect(&host_address).await?;
        host_stream.write_all(&http_data).await?;
        host_stream.flush().await?;

        let mut buffer = [0u8; 1024];

        loop {
            let n = host_stream.read_until(&mut buffer).await?;
            println!("read {} bytes", n);
            stream.write_all(&buffer[..n]).await?;
            if n == 0 {
                break;
            }
        }
        println!("end");
        stream.flush().await?;
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:8080").await?;

    loop {
        let (stream, _) = listener.accept().await?;

        tokio::spawn(async move {
            let resut = handle_connection(stream).await;

            if let Err(e) = resut {
                println!("an error occured; error = {:?}", e);
            }
        });
    }
}
