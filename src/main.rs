mod ethernet;
mod ipv4;
mod icmp;
mod checksum;
mod cli;
mod tun;

fn main() {
    println!("MiniNetStack starting...\n");

    if let Err(e) = tun::start_tun_interface() {
        eprintln!("Error: {}", e);
    }
}