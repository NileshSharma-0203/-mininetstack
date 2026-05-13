use std::io::{Read, Write};

use crate::checksum::compute_checksum;
use crate::icmp::IcmpPacket;
use crate::ipv4::Ipv4Packet;
use crate::udp::UdpPacket;

pub fn start_tun_interface() -> Result<(), Box<dyn std::error::Error>> {
    let mut config = tun::Configuration::default();

    config
        .address((10, 0, 0, 1))
        .netmask((255, 255, 255, 0))
        .up();

    let mut dev = tun::create(&config)?;

    println!("TUN interface created.");
    println!("Waiting for packets...\n");

    let mut buffer = [0u8; 1504];

    loop {
        let n = dev.read(&mut buffer)?;

        println!("========================================");
        println!("Received packet: {} bytes", n);

        let raw_data = &buffer[..n];

        let (packet_data, has_tun_header) =
            if !raw_data.is_empty() && (raw_data[0] >> 4) == 4 {
                (raw_data, false)
            } else if raw_data.len() > 4 && (raw_data[4] >> 4) == 4 {
                println!("Detected 4-byte TUN header. Skipping it.");
                (&raw_data[4..], true)
            } else {
                println!("Non-IPv4 packet received. Skipping.");
                continue;
            };

        let ipv4_packet = match Ipv4Packet::parse(packet_data) {
            Ok(packet) => packet,
            Err(e) => {
                println!("IPv4 Parse Error: {}", e);
                continue;
            }
        };

        println!("IPv4 Packet");
        println!("Source IP: {}", Ipv4Packet::format_ip(&ipv4_packet.source_ip));
        println!(
            "Destination IP: {}",
            Ipv4Packet::format_ip(&ipv4_packet.destination_ip)
        );
        println!("TTL: {}", ipv4_packet.ttl);
        println!("Protocol: {}", ipv4_packet.protocol);

        match ipv4_packet.protocol {
    // ICMP
    1 => {
        let icmp_packet = match IcmpPacket::parse(ipv4_packet.payload) {
            Ok(packet) => packet,
            Err(e) => {
                println!("ICMP Parse Error: {}", e);
                continue;
            }
        };

        println!("ICMP Packet");

        println!(
            "Type: {} ({})",
            icmp_packet.icmp_type,
            IcmpPacket::icmp_type_name(
                icmp_packet.icmp_type
            )
        );

        println!("Code: {}", icmp_packet.code);

        println!(
            "Checksum Valid: {}",
            IcmpPacket::validate_checksum(
                ipv4_packet.payload
            )
        );

        if icmp_packet.icmp_type == 8 {
            println!("Echo Request received.");

            let reply =
                build_icmp_echo_reply(&ipv4_packet);

            if has_tun_header {
                let mut framed_reply = Vec::new();

                framed_reply.extend_from_slice(
                    &[0x00, 0x00, 0x08, 0x00]
                );

                framed_reply.extend_from_slice(&reply);

                dev.write_all(&framed_reply)?;
            } else {
                dev.write_all(&reply)?;
            }

            println!("Echo Reply sent.");
        }
    }

    // UDP
    17 => {
        let udp_packet =
            match UdpPacket::parse(ipv4_packet.payload) {
                Ok(packet) => packet,
                Err(e) => {
                    println!("UDP Parse Error: {}", e);
                    continue;
                }
            };

        println!("UDP Packet");

        println!(
            "Source Port: {}",
            udp_packet.source_port
        );

        println!(
            "Destination Port: {}",
            udp_packet.destination_port
        );

        println!("Length: {}", udp_packet.length);

        println!(
            "Checksum: 0x{:04x}",
            udp_packet.checksum
        );

        println!(
            "Payload Length: {}",
            udp_packet.payload.len()
        );

        if let Ok(text) =
            std::str::from_utf8(udp_packet.payload)
        {
            println!("Payload Text: {}", text);
        }
    }

    _ => {
        println!(
            "Unsupported protocol: {}",
            ipv4_packet.protocol
        );
    }
}

        let icmp_packet = match IcmpPacket::parse(ipv4_packet.payload) {
            Ok(packet) => packet,
            Err(e) => {
                println!("ICMP Parse Error: {}", e);
                continue;
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
            println!("Echo Request received. Sending Echo Reply...");

            let reply = build_icmp_echo_reply(&ipv4_packet);

            if has_tun_header {
                let mut framed_reply = Vec::new();

                // Linux TUN packet information header:
                // flags = 0x0000, protocol = 0x0800 IPv4
                framed_reply.extend_from_slice(&[0x00, 0x00, 0x08, 0x00]);
                framed_reply.extend_from_slice(&reply);

                dev.write_all(&framed_reply)?;
            } else {
                dev.write_all(&reply)?;
            }

            println!("Echo Reply sent.");
        }
    }
}

fn build_icmp_echo_reply(ipv4_packet: &Ipv4Packet) -> Vec<u8> {
    let icmp_request = ipv4_packet.payload;

    let total_length = 20 + icmp_request.len();

    let mut reply = vec![0u8; total_length];

    // IPv4 header
    reply[0] = 0x45; // version 4, header length 5
    reply[1] = 0x00; // DSCP/ECN
    reply[2..4].copy_from_slice(&(total_length as u16).to_be_bytes());
    reply[4..6].copy_from_slice(&0u16.to_be_bytes()); // identification
    reply[6..8].copy_from_slice(&0u16.to_be_bytes()); // flags/fragment offset
    reply[8] = 64; // TTL
    reply[9] = 1; // ICMP
    reply[10..12].copy_from_slice(&0u16.to_be_bytes()); // checksum placeholder

    // Swap source and destination IPs
    reply[12..16].copy_from_slice(&ipv4_packet.destination_ip);
    reply[16..20].copy_from_slice(&ipv4_packet.source_ip);

    let ipv4_checksum = compute_checksum(&reply[0..20]);
    reply[10..12].copy_from_slice(&ipv4_checksum.to_be_bytes());

    // ICMP reply
    let icmp_start = 20;

    reply[icmp_start] = 0; // Echo Reply
    reply[icmp_start + 1] = 0; // Code
    reply[icmp_start + 2] = 0;
    reply[icmp_start + 3] = 0;

    // Copy identifier, sequence number, and payload from request
    reply[icmp_start + 4..].copy_from_slice(&icmp_request[4..]);

    let icmp_checksum = compute_checksum(&reply[icmp_start..]);
    reply[icmp_start + 2..icmp_start + 4].copy_from_slice(&icmp_checksum.to_be_bytes());

    reply
}