#[derive(Debug)]
pub struct UdpPacket<'a> {
    pub source_port: u16,
    pub destination_port: u16,
    pub length: u16,
    pub checksum: u16,
    pub payload: &'a [u8],
}

impl<'a> UdpPacket<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self, String> {
        if data.len() < 8 {
            return Err("UDP packet too short".to_string());
        }

        let source_port =
            u16::from_be_bytes([data[0], data[1]]);

        let destination_port =
            u16::from_be_bytes([data[2], data[3]]);

        let length =
            u16::from_be_bytes([data[4], data[5]]);

        let checksum =
            u16::from_be_bytes([data[6], data[7]]);

        if data.len() < length as usize {
            return Err(
                "UDP length larger than packet".to_string()
            );
        }

        let payload = &data[8..length as usize];

        Ok(UdpPacket {
            source_port,
            destination_port,
            length,
            checksum,
            payload,
        })
    }
}