use mozim::{DhcpV4Client, DhcpV4Config};

fn main() {
    let mut log_builder = env_logger::Builder::new();
    log_builder.filter(Some("mozim"), log::LevelFilter::Debug);
    log_builder.init();

    let mut config = DhcpV4Config::new("eth1").unwrap();
    config.set_host_name("Gris-Laptop");
    config.use_host_name_as_client_id();
    let cli = DhcpV4Client::new(config);

    let lease = cli.request(None).unwrap();

    println!("Got lease {:?}", lease);

    loop {
        match cli.run(&lease) {
            Ok(lease) => {
                println!("new lease {:?}", lease);
            }

            Err(e) => {
                println!("error {:?}", e);
                break;
            }
        }
    }
}
