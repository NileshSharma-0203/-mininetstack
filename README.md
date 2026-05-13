# MiniNetStack

MiniNetStack is a userspace TCP/IP networking stack implemented in Rust using a Linux TUN interface.

The project manually implements core networking protocols including IPv4, ICMP, UDP, TCP, TCP connection management, and a minimal HTTP server without relying on the operating system’s transport stack.

The goal of the project is to explore low-level networking internals, packet processing, transport-layer protocol design, and systems programming by building networking functionality from first principles.

---

# Features

## Internet Layer
- IPv4 packet parsing
- IPv4 header validation
- IPv4 checksum verification
- Protocol demultiplexing
- Raw packet processing through Linux TUN interface

## ICMP
- ICMP packet parsing
- ICMP checksum validation
- ICMP Echo Reply support
- Functional `ping` support

## UDP
- UDP packet parsing
- UDP payload extraction
- UDP echo server implementation

## TCP
- TCP header parsing
- TCP checksum generation
- TCP pseudo-header checksum handling
- TCP SYN/SYN-ACK/ACK three-way handshake
- TCP sequence number tracking
- TCP acknowledgement handling
- TCP connection state machine
- TCP connection table management
- TCP FIN teardown handling
- Multi-client-ready connection architecture

## HTTP Server
- Minimal HTTP/1.1 response handling
- HTTP request parsing
- HTTP response generation over custom TCP stack
- Compatible with `curl` and browsers

---

# Architecture

The stack is implemented with a modular design:

```text
src/
├── checksum/
├── ethernet/
├── icmp/
├── ipv4/
├── tcp/
├── tun/
└── udp/
```

## Module Responsibilities

| Module | Responsibility |
|---|---|
| checksum | Internet checksum implementation |
| ethernet | Ethernet frame parsing |
| ipv4 | IPv4 packet parsing and validation |
| icmp | ICMP protocol handling |
| udp | UDP transport handling |
| tcp | TCP packet parsing |
| tun | TUN interface integration and packet processing |

---

# Technologies Used

- Rust
- Linux TUN/TAP interface
- Raw packet processing
- Systems programming
- Transport-layer protocol implementation
- Userspace networking

---

# How It Works

MiniNetStack operates as a userspace networking stack connected to the Linux kernel through a virtual TUN device.

Packet flow:

```text
Application (curl / ping / nc)
        ↓
Linux Kernel Networking Stack
        ↓
TUN Interface
        ↓
MiniNetStack (Userspace)
        ↓
IPv4 / ICMP / UDP / TCP Processing
        ↓
Response Packet Generation
        ↓
Back to Linux Kernel
```

The stack manually parses raw packets, validates checksums, manages TCP state transitions, and generates response packets entirely in userspace.

---

# Implemented TCP State Machine

```text
LISTEN
   ↓
SYN_RECEIVED
   ↓
ESTABLISHED
   ↓
CLOSE_WAIT
   ↓
CLOSED
```

The stack currently supports:
- TCP connection establishment
- data transmission
- connection teardown
- connection cleanup

---

# Running the Project

## Requirements

- Linux
- Rust toolchain
- Cargo

Install Rust:

```bash
curl https://sh.rustup.rs -sSf | sh
```

---

# Build

```bash
cargo build
```

---

# Run

```bash
cargo run
```

---

# Testing

## ICMP Ping

```bash
ping 10.0.0.2
```

---

## UDP Echo

```bash
nc -u 10.0.0.2 8080
```

---

## TCP Connection

```bash
nc 10.0.0.2 8080
```

---

## HTTP Server

```bash
curl http://10.0.0.2:8080
```

Example response:

```text
Hello from MiniNetStack!
```

---

# Example Capabilities

## Working ICMP Echo Replies

```text
ping 10.0.0.2
```

## TCP Three-Way Handshake

```text
SYN
SYN-ACK
ACK
```

## HTTP Response Over Custom TCP Stack

```http
HTTP/1.1 200 OK
Content-Type: text/plain
Content-Length: 27

Hello from MiniNetStack!
```

---

# Learning Goals

This project explores:

- Network protocol internals
- TCP/IP stack architecture
- Transport-layer protocol design
- Packet serialization/deserialization
- Internet checksum algorithms
- Connection state management
- Linux networking internals
- Systems programming in Rust
- Userspace networking

---

# Future Improvements

Planned improvements include:

- TCP retransmission support
- Sliding window implementation
- Congestion control
- Async event loop integration
- Ethernet frame transmission
- ARP support
- DNS parsing
- Improved HTTP parsing
- Concurrent packet processing
- Userspace socket API

---

# Why This Project Exists

Most software engineers use networking through high-level socket APIs.

MiniNetStack explores the lower layers underneath those APIs by implementing core networking protocols manually from raw packets upward.

The project serves as both a learning exercise and a demonstration of systems programming, networking, and protocol engineering concepts.

---

# License

MIT License
