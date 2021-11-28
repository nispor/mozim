use mozim::DhcpSocket;

fn main() {
    let config = DhcpClientConfig::new();
    config.iface_name = "eth1".to_string();
    config.hostname = "Gris-Laptop".to_string();
    config.use_hostname_as_uuid();
    config.set_lease_ip("192.0.3.100");
    let (cli, comm) = DhcpClient::new(config).unwrap();

    println!("Got IP {:?}", cli.request().unwrap());
    std::thread::spawn(move |cli| cli.run());

    loop {
        std::thread::sleep(std::time::Duration::from_millis(100));
        println!("{:?}", comm.query_state());
    }
}
