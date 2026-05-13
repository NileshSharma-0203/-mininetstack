use crate::checksum::compute_checksum;
#[derive(Debug)]
pub struct IcmpPacket<'a> {
    pub icmp_type: u8,
    pub code: u8,
    pub checksum: u16,
    pub payload: &'a [u8],
}

impl<'a> IcmpPacket<'a> {
    pub fn validate_checksum(data: &[u8]) -> bool {
    compute_checksum(data) == 0
}
    pub fn parse(data: &'a [u8]) -> Result<Self, String> {
        if data.len() < 4 {
            return Err("ICMP packet too short".to_string());
        }

        let icmp_type = data[0];
        let code = data[1];

        let checksum = u16::from_be_bytes([data[2], data[3]]);

        let payload = &data[4..];

        Ok(IcmpPacket {
            icmp_type,
            code,
            checksum,
            payload,
        })
    }

    pub fn icmp_type_name(icmp_type: u8) -> &'static str {
        match icmp_type {
            0 => "Echo Reply",
            8 => "Echo Request",
            _ => "Unknown",
        }
    }
}