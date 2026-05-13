use std::collections::HashMap;
use std::io::{Read, Write};

use crate::checksum::compute_checksum;
use crate::icmp::IcmpPacket;
use crate::ipv4::Ipv4Packet;
use crate::tcp::TcpPacket;
use crate::udp::UdpPacket;

const STACK_IP: [u8; 4] = [10, 0, 0, 2];
const TCP_LISTEN_PORT: u16 = 8080;
const INITIAL_SERVER_SEQ: u32 = 1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct ConnectionKey {
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TcpState {
    SynReceived,
    Established,
    CloseWait,
    Closed,
}

#[derive(Debug)]
struct TcpConnection {
    state: TcpState,
    send_seq: u32,
    recv_seq: u32,
}

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
    let mut connections: HashMap<ConnectionKey, TcpConnection> = HashMap::new();

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
        println!(
            "IPv4 Checksum Valid: {}",
            Ipv4Packet::validate_checksum(packet_data)
        );

        match ipv4_packet.protocol {
            1 => handle_icmp(&mut dev, &ipv4_packet, has_tun_header)?,
            6 => handle_tcp(&mut dev, &ipv4_packet, has_tun_header, &mut connections)?,
            17 => handle_udp(&mut dev, &ipv4_packet, has_tun_header)?,
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
        write_packet(dev, &reply, has_tun_header)?;

        println!("Echo Reply sent.");
    }

    Ok(())
}

fn handle_udp(
    dev: &mut tun::platform::Device,
    ipv4_packet: &Ipv4Packet,
    has_tun_header: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let udp_packet = match UdpPacket::parse(ipv4_packet.payload) {
        Ok(packet) => packet,
        Err(e) => {
            println!("UDP Parse Error: {}", e);
            return Ok(());
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

    if udp_packet.destination_port == TCP_LISTEN_PORT {
        println!("UDP Echo request received. Sending reply...");

        let reply = build_udp_echo_reply(ipv4_packet, &udp_packet);
        write_packet(dev, &reply, has_tun_header)?;

        println!("UDP Echo reply sent.");
    }

    Ok(())
}

fn handle_tcp(
    dev: &mut tun::platform::Device,
    ipv4_packet: &Ipv4Packet,
    has_tun_header: bool,
    connections: &mut HashMap<ConnectionKey, TcpConnection>,
) -> Result<(), Box<dyn std::error::Error>> {
    let tcp_packet = match TcpPacket::parse(ipv4_packet.payload) {
        Ok(packet) => packet,
        Err(e) => {
            println!("TCP Parse Error: {}", e);
            return Ok(());
        }
    };

    println!("TCP Packet");
    println!("Source Port: {}", tcp_packet.source_port);
    println!("Destination Port: {}", tcp_packet.destination_port);
    println!("Sequence Number: {}", tcp_packet.sequence_number);
    println!(
        "Acknowledgement Number: {}",
        tcp_packet.acknowledgement_number
    );
    println!("Data Offset: {}", tcp_packet.data_offset);
    println!("Window Size: {}", tcp_packet.window_size);
    println!("Checksum: 0x{:04x}", tcp_packet.checksum);
    println!("Urgent Pointer: {}", tcp_packet.urgent_pointer);

    println!("Flags:");
    println!("  SYN: {}", tcp_packet.syn());
    println!("  ACK: {}", tcp_packet.ack());
    println!("  FIN: {}", tcp_packet.fin());

    println!("Payload Length: {}", tcp_packet.payload.len());

    if tcp_packet.destination_port != TCP_LISTEN_PORT {
        println!("TCP packet ignored. Port not listening.");
        return Ok(());
    }

    let key = ConnectionKey {
        src_ip: ipv4_packet.source_ip,
        dst_ip: ipv4_packet.destination_ip,
        src_port: tcp_packet.source_port,
        dst_port: tcp_packet.destination_port,
    };

    if tcp_packet.syn() && !tcp_packet.ack() {
        println!("TCP state: LISTEN");
        println!("TCP SYN received. Creating connection...");

        let client_next_seq = tcp_packet.sequence_number.wrapping_add(1);

        connections.insert(
            key,
            TcpConnection {
                state: TcpState::SynReceived,
                send_seq: INITIAL_SERVER_SEQ,
                recv_seq: client_next_seq,
            },
        );

        let reply = build_tcp_syn_ack_reply(ipv4_packet, &tcp_packet, INITIAL_SERVER_SEQ);
        write_packet(dev, &reply, has_tun_header)?;

        println!("TCP state: SYN_RECEIVED");
        println!("Connection table size: {}", connections.len());
        println!("TCP SYN-ACK sent.");
        return Ok(());
    }

    let mut should_remove_connection = false;

    let Some(connection) = connections.get_mut(&key) else {
        println!("No TCP connection found for this packet. Ignoring.");
        return Ok(());
    };

    match connection.state {
        TcpState::SynReceived => {
            if tcp_packet.ack()
                && tcp_packet.payload.is_empty()
                && tcp_packet.acknowledgement_number == connection.send_seq.wrapping_add(1)
            {
                connection.state = TcpState::Established;
                connection.send_seq = connection.send_seq.wrapping_add(1);

                println!("TCP state: ESTABLISHED");
                println!("Final ACK received. TCP handshake complete.");
                println!("Connection table size: {}", connections.len());
            } else {
                println!("Unexpected packet while in SYN_RECEIVED.");
            }
        }

        TcpState::Established => {
            if tcp_packet.fin() {
                println!("TCP FIN received.");
                println!("TCP state: CLOSE_WAIT");

                let ack_number = tcp_packet.sequence_number.wrapping_add(1);
                connection.recv_seq = ack_number;

                let ack_reply = build_tcp_control_packet(
                    ipv4_packet,
                    &tcp_packet,
                    connection.send_seq,
                    connection.recv_seq,
                    0x10,
                );
                write_packet(dev, &ack_reply, has_tun_header)?;

                println!("ACK sent for FIN.");

                let fin_ack_reply = build_tcp_control_packet(
                    ipv4_packet,
                    &tcp_packet,
                    connection.send_seq,
                    connection.recv_seq,
                    0x11,
                );
                write_packet(dev, &fin_ack_reply, has_tun_header)?;

                connection.send_seq = connection.send_seq.wrapping_add(1);
                connection.state = TcpState::CloseWait;

                println!("FIN-ACK sent.");
                return Ok(());
            }

            if tcp_packet.ack() && !tcp_packet.payload.is_empty() {
                println!("TCP state: ESTABLISHED");
                println!("TCP data received.");

                if let Ok(text) = std::str::from_utf8(tcp_packet.payload) {
                    println!("TCP Payload Text:\n{}", text.trim_end());
                }

                let expected_seq = connection.recv_seq;

                if tcp_packet.sequence_number != expected_seq {
                    println!(
                        "Duplicate/out-of-order TCP data detected. Expected seq {}, got {}.",
                        expected_seq, tcp_packet.sequence_number
                    );

                    let ack_reply = build_tcp_control_packet(
                        ipv4_packet,
                        &tcp_packet,
                        connection.send_seq,
                        connection.recv_seq,
                        0x10,
                    );
                    write_packet(dev, &ack_reply, has_tun_header)?;

                    println!("ACK resent. Duplicate data not processed.");
                    return Ok(());
                }

                let ack_number = tcp_packet
                    .sequence_number
                    .wrapping_add(tcp_packet.payload.len() as u32);

                connection.recv_seq = ack_number;

                let http_response = build_http_response(tcp_packet.payload);

                let reply = build_tcp_http_reply(
                    ipv4_packet,
                    &tcp_packet,
                    connection.send_seq,
                    connection.recv_seq,
                    &http_response,
                );

                write_packet(dev, &reply, has_tun_header)?;

                connection.send_seq = connection
                    .send_seq
                    .wrapping_add(http_response.len() as u32);

                println!("HTTP response sent over custom TCP stack.");
                println!("Updated send_seq: {}", connection.send_seq);
                println!("Updated recv_seq: {}", connection.recv_seq);
            } else if tcp_packet.ack() && tcp_packet.payload.is_empty() {
                println!("TCP state: ESTABLISHED");
                println!("ACK received.");
            }
        }

        TcpState::CloseWait => {
            if tcp_packet.ack() {
                println!("Final ACK for our FIN received.");
                println!("TCP state: CLOSED");
                connection.state = TcpState::Closed;
                should_remove_connection = true;
            }
        }

        TcpState::Closed => {
            println!("TCP state: CLOSED");
            should_remove_connection = true;
        }
    }

    if should_remove_connection {
        connections.remove(&key);
        println!("Connection removed.");
        println!("Connection table size: {}", connections.len());
    }

    Ok(())
}

fn write_packet(
    dev: &mut tun::platform::Device,
    packet: &[u8],
    has_tun_header: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if has_tun_header {
        let mut framed_packet = Vec::new();

        framed_packet.extend_from_slice(&[0x00, 0x00, 0x08, 0x00]);
        framed_packet.extend_from_slice(packet);

        dev.write_all(&framed_packet)?;
    } else {
        dev.write_all(packet)?;
    }

    Ok(())
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

fn build_udp_echo_reply(ipv4_packet: &Ipv4Packet, udp_packet: &UdpPacket) -> Vec<u8> {
    let udp_payload = udp_packet.payload;
    let udp_length = 8 + udp_payload.len();
    let total_length = 20 + udp_length;

    let mut reply = vec![0u8; total_length];

    reply[0] = 0x45;
    reply[1] = 0x00;
    reply[2..4].copy_from_slice(&(total_length as u16).to_be_bytes());
    reply[4..6].copy_from_slice(&0u16.to_be_bytes());
    reply[6..8].copy_from_slice(&0u16.to_be_bytes());
    reply[8] = 64;
    reply[9] = 17;
    reply[10..12].copy_from_slice(&0u16.to_be_bytes());

    reply[12..16].copy_from_slice(&ipv4_packet.destination_ip);
    reply[16..20].copy_from_slice(&ipv4_packet.source_ip);

    let ipv4_checksum = compute_checksum(&reply[0..20]);
    reply[10..12].copy_from_slice(&ipv4_checksum.to_be_bytes());

    let udp_start = 20;

    reply[udp_start..udp_start + 2].copy_from_slice(&udp_packet.destination_port.to_be_bytes());
    reply[udp_start + 2..udp_start + 4].copy_from_slice(&udp_packet.source_port.to_be_bytes());
    reply[udp_start + 4..udp_start + 6].copy_from_slice(&(udp_length as u16).to_be_bytes());
    reply[udp_start + 6..udp_start + 8].copy_from_slice(&0u16.to_be_bytes());
    reply[udp_start + 8..].copy_from_slice(udp_payload);

    reply
}

fn build_http_response(request_payload: &[u8]) -> Vec<u8> {
    let request_text = std::str::from_utf8(request_payload).unwrap_or("");

    let body = if request_text.starts_with("GET / ") || request_text.starts_with("GET / HTTP") {
        "Hello from MiniNetStack!\n"
    } else if request_text.starts_with("GET /health") {
        "OK\n"
    } else {
        "MiniNetStack HTTP Server\n"
    };

    let response = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: text/plain\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         Server: MiniNetStack\r\n\
         \r\n\
         {}",
        body.len(),
        body
    );

    response.into_bytes()
}

fn build_tcp_syn_ack_reply(
    ipv4_packet: &Ipv4Packet,
    tcp_packet: &TcpPacket,
    server_seq: u32,
) -> Vec<u8> {
    let ack_number = tcp_packet.sequence_number.wrapping_add(1);

    build_tcp_packet(
        ipv4_packet,
        tcp_packet,
        server_seq,
        ack_number,
        0x12,
        &[],
    )
}

fn build_tcp_http_reply(
    ipv4_packet: &Ipv4Packet,
    tcp_packet: &TcpPacket,
    sequence_number: u32,
    acknowledgement_number: u32,
    http_response: &[u8],
) -> Vec<u8> {
    build_tcp_packet(
        ipv4_packet,
        tcp_packet,
        sequence_number,
        acknowledgement_number,
        0x18,
        http_response,
    )
}

fn build_tcp_control_packet(
    ipv4_packet: &Ipv4Packet,
    tcp_packet: &TcpPacket,
    sequence_number: u32,
    acknowledgement_number: u32,
    flags: u8,
) -> Vec<u8> {
    build_tcp_packet(
        ipv4_packet,
        tcp_packet,
        sequence_number,
        acknowledgement_number,
        flags,
        &[],
    )
}

fn build_tcp_packet(
    ipv4_packet: &Ipv4Packet,
    tcp_packet: &TcpPacket,
    sequence_number: u32,
    acknowledgement_number: u32,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let tcp_header_len = 20;
    let tcp_length = tcp_header_len + payload.len();
    let total_length = 20 + tcp_length;

    let mut reply = vec![0u8; total_length];

    reply[0] = 0x45;
    reply[1] = 0x00;
    reply[2..4].copy_from_slice(&(total_length as u16).to_be_bytes());
    reply[4..6].copy_from_slice(&0u16.to_be_bytes());
    reply[6..8].copy_from_slice(&0u16.to_be_bytes());
    reply[8] = 64;
    reply[9] = 6;
    reply[10..12].copy_from_slice(&0u16.to_be_bytes());

    reply[12..16].copy_from_slice(&ipv4_packet.destination_ip);
    reply[16..20].copy_from_slice(&ipv4_packet.source_ip);

    let ipv4_checksum = compute_checksum(&reply[0..20]);
    reply[10..12].copy_from_slice(&ipv4_checksum.to_be_bytes());

    let tcp_start = 20;

    reply[tcp_start..tcp_start + 2].copy_from_slice(&tcp_packet.destination_port.to_be_bytes());
    reply[tcp_start + 2..tcp_start + 4].copy_from_slice(&tcp_packet.source_port.to_be_bytes());
    reply[tcp_start + 4..tcp_start + 8].copy_from_slice(&sequence_number.to_be_bytes());
    reply[tcp_start + 8..tcp_start + 12].copy_from_slice(&acknowledgement_number.to_be_bytes());

    reply[tcp_start + 12] = 5 << 4;
    reply[tcp_start + 13] = flags;

    reply[tcp_start + 14..tcp_start + 16].copy_from_slice(&64240u16.to_be_bytes());
    reply[tcp_start + 16..tcp_start + 18].copy_from_slice(&0u16.to_be_bytes());
    reply[tcp_start + 18..tcp_start + 20].copy_from_slice(&0u16.to_be_bytes());

    if !payload.is_empty() {
        reply[tcp_start + tcp_header_len..].copy_from_slice(payload);
    }

    let tcp_checksum = compute_tcp_checksum(
        &ipv4_packet.destination_ip,
        &ipv4_packet.source_ip,
        &reply[tcp_start..],
    );

    reply[tcp_start + 16..tcp_start + 18].copy_from_slice(&tcp_checksum.to_be_bytes());

    reply
}

fn compute_tcp_checksum(
    source_ip: &[u8; 4],
    destination_ip: &[u8; 4],
    tcp_segment: &[u8],
) -> u16 {
    let mut pseudo_packet = Vec::new();

    pseudo_packet.extend_from_slice(source_ip);
    pseudo_packet.extend_from_slice(destination_ip);
    pseudo_packet.push(0);
    pseudo_packet.push(6);
    pseudo_packet.extend_from_slice(&(tcp_segment.len() as u16).to_be_bytes());
    pseudo_packet.extend_from_slice(tcp_segment);

    compute_checksum(&pseudo_packet)
}

fn protocol_name(protocol: u8) -> &'static str {
    match protocol {
        1 => "ICMP",
        6 => "TCP",
        17 => "UDP",
        _ => "Unknown",
    }
}