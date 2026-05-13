use std::io::{Read, Write};

use crate::checksum::compute_checksum;
use crate::icmp::IcmpPacket;
use crate::ipv4::Ipv4Packet;
use crate::udp::UdpPacket;

const STACK_IP: [u8; 4] = [10, 0, 0, 2];

pub fn start_tun_interface() -> Result<(), Box<dyn std::error::Error>> {
    let mut config = tun::Configuration::default();

    config
        .address((10, 0, 0, 1))
        .netmask((255, 255, 255, 0))
        .up();

    let mut dev = tun::create(&config)?;

    println!("TUN interface created.");
    println!("MiniNetStack virtual IP: 10.0.0.2");
    println!("Waiting for packets...\n");

    let mut buffer = [0u8; 1504];

    loop {
        let n = dev.read(&mut buffer)?;
        let raw_data = &buffer[..n];

        let (packet_data, has_tun_header) =
            if !raw_data.is_empty() && (raw_data[0] >> 4) == 4 {
                (raw_data, false)
            } else if raw_data.len() > 4 && (raw_data[4] >> 4) == 4 {
                (&raw_data[4..], true)
            } else {
                continue;
            };

        let ipv4_packet = match Ipv4Packet::parse(packet_data) {
            Ok(packet) => packet,
            Err(_) => continue,
        };

        if ipv4_packet.destination_ip != STACK_IP {
            continue;
        }

        println!("========================================");
        println!("IPv4 Packet");
        println!("Source IP: {}", Ipv4Packet::format_ip(&ipv4_packet.source_ip));
        println!(
            "Destination IP: {}",
            Ipv4Packet::format_ip(&ipv4_packet.destination_ip)
        );
        println!("TTL: {}", ipv4_packet.ttl);
        println!("Protocol: {}", protocol_name(ipv4_packet.protocol));

        match ipv4_packet.protocol {
            1 => handle_icmp(&mut dev, &ipv4_packet, has_tun_header)?,
            17 => handle_udp(&ipv4_packet),
            _ => println!("Unsupported protocol: {}", ipv4_packet.protocol),
        }
    }
}

fn handle_icmp(
    dev: &mut tun::platform::Device,
    ipv4_packet: &Ipv4Packet,
    has_tun_header: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let icmp_packet = match IcmpPacket::parse(ipv4_packet.payload) {
        Ok(packet) => packet,
        Err(e) => {
            println!("ICMP Parse Error: {}", e);
            return Ok(());
        }
    };

    println!("ICMP Packet");
    println!(
        "Type: {} ({})",
        icmp_packet.icmp_type,
        IcmpPacket::icmp_type_name(icmp_packet.icmp_type)
    );
    println!("Code: {}", icmp_packet.code);
    println!(
        "Checksum Valid: {}",
        IcmpPacket::validate_checksum(ipv4_packet.payload)
    );

    if icmp_packet.icmp_type == 8 {
        println!("Echo Request received.");

        let reply = build_icmp_echo_reply(ipv4_packet);

        if has_tun_header {
            let mut framed_reply = Vec::new();
            framed_reply.extend_from_slice(&[0x00, 0x00, 0x08, 0x00]);
            framed_reply.extend_from_slice(&reply);
            dev.write_all(&framed_reply)?;
        } else {
            dev.write_all(&reply)?;
        }

        println!("Echo Reply sent.");
    }

    Ok(())
}

fn handle_udp(ipv4_packet: &Ipv4Packet) {
    let udp_packet = match UdpPacket::parse(ipv4_packet.payload) {
        Ok(packet) => packet,
        Err(e) => {
            println!("UDP Parse Error: {}", e);
            return;
        }
    };

    println!("UDP Packet");
    println!("Source Port: {}", udp_packet.source_port);
    println!("Destination Port: {}", udp_packet.destination_port);
    println!("Length: {}", udp_packet.length);
    println!("Checksum: 0x{:04x}", udp_packet.checksum);
    println!("Payload Length: {}", udp_packet.payload.len());

    if let Ok(text) = std::str::from_utf8(udp_packet.payload) {
        println!("Payload Text: {}", text.trim_end());
    }
}

fn build_icmp_echo_reply(ipv4_packet: &Ipv4Packet) -> Vec<u8> {
    let icmp_request = ipv4_packet.payload;
    let total_length = 20 + icmp_request.len();

    let mut reply = vec![0u8; total_length];

    reply[0] = 0x45;
    reply[1] = 0x00;
    reply[2..4].copy_from_slice(&(total_length as u16).to_be_bytes());
    reply[4..6].copy_from_slice(&0u16.to_be_bytes());
    reply[6..8].copy_from_slice(&0u16.to_be_bytes());
    reply[8] = 64;
    reply[9] = 1;
    reply[10..12].copy_from_slice(&0u16.to_be_bytes());

    reply[12..16].copy_from_slice(&ipv4_packet.destination_ip);
    reply[16..20].copy_from_slice(&ipv4_packet.source_ip);

    let ipv4_checksum = compute_checksum(&reply[0..20]);
    reply[10..12].copy_from_slice(&ipv4_checksum.to_be_bytes());

    let icmp_start = 20;

    reply[icmp_start] = 0;
    reply[icmp_start + 1] = 0;
    reply[icmp_start + 2] = 0;
    reply[icmp_start + 3] = 0;

    reply[icmp_start + 4..].copy_from_slice(&icmp_request[4..]);

    let icmp_checksum = compute_checksum(&reply[icmp_start..]);
    reply[icmp_start + 2..icmp_start + 4].copy_from_slice(&icmp_checksum.to_be_bytes());

    reply
}

fn protocol_name(protocol: u8) -> &'static str {
    match protocol {
        1 => "ICMP",
        6 => "TCP",
        17 => "UDP",
        _ => "Unknown",
    }
}