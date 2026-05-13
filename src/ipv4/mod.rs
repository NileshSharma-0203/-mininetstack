#[derive(Debug)]
pub struct Ipv4Packet<'a> {
    pub version: u8,
    pub header_length: u8,
    pub total_length: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub source_ip: [u8; 4],
    pub destination_ip: [u8; 4],
    pub payload: &'a [u8],
}

impl<'a> Ipv4Packet<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self, String> {
        if data.len() < 20 {
            return Err("IPv4 packet too short".to_string());
        }

        let version = data[0] >> 4;
        let header_length = (data[0] & 0x0F) * 4;

        if data.len() < header_length as usize {
            return Err("Invalid IPv4 header length".to_string());
        }

        let total_length = u16::from_be_bytes([data[2], data[3]]);
        let ttl = data[8];
        let protocol = data[9];

        let source_ip = data[12..16]
            .try_into()
            .map_err(|_| "Invalid source IP")?;

        let destination_ip = data[16..20]
            .try_into()
            .map_err(|_| "Invalid destination IP")?;

        let payload = &data[header_length as usize..];

        Ok(Ipv4Packet {
            version,
            header_length,
            total_length,
            ttl,
            protocol,
            source_ip,
            destination_ip,
            payload,
        })
    }

    pub fn format_ip(ip: &[u8; 4]) -> String {
        format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
    }
}