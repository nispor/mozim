use mozim::DhcpSocket;

fn main() {
    let mut sock = DhcpSocket::new("eth1").unwrap();
    sock.send_dhcp_discovery("Gris-Laptop").unwrap();
    loop {
        println!("{:?}", sock.recv_dhcp_reply().unwrap());
    }
}
