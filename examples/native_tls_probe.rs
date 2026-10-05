//! Local interop harness. Not a production CLI or trust configuration mechanism.
#[cfg(feature = "tls-native")]
fn main() {
    use iron_privacy_guard::{error::Result, tls::Client};
    let run = || -> Result<()> {
        let args: Vec<String> = std::env::args().collect();
        assert_eq!(args.len(), 5, "port hostname root.der update|plain");
        let port: u16 = args[1].parse().expect("port");
        let root = std::fs::read(&args[3])?;
        let socket = std::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port))?;
        let mut client = Client::connect(socket, &args[2], &[root])?;
        if args[4] == "update" {
            client.update_keys()?;
        }
        client.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")?;
        let response = client.read_to_end(65536)?;
        println!("{}", String::from_utf8_lossy(&response));
        Ok(())
    };
    if let Err(e) = run() {
        eprintln!("{}: {}", e.code, e.message);
        std::process::exit(1);
    }
}
#[cfg(not(feature = "tls-native"))]
fn main() {
    eprintln!("Enable tls-native to run this local test harness");
}
