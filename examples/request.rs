
use dhcpc::DhcpSocket;

fn main() {
    let mut sock = DhcpSocket::new("veth1").unwrap();
    sock.send_dhcp_request("Gris-Laptop").unwrap();
    println!("{:?}", sock.recv_dhcp_reply().unwrap());
}
