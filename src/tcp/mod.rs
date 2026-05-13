//tcp/mod.rs
#[derive(Debug)]
pub struct TcpPacket<'a> {
    pub source_port: u16,
    pub destination_port: u16,
    pub sequence_number: u32,
    pub acknowledgement_number: u32,
    pub data_offset: u8,
    pub flags: u16,
    pub window_size: u16,
    pub checksum: u16,
    pub urgent_pointer: u16,
    pub payload: &'a [u8],
}

impl<'a> TcpPacket<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self, String> {
        if data.len() < 20 {
            return Err("TCP packet too short".to_string());
        }

        let source_port =
            u16::from_be_bytes([data[0], data[1]]);

        let destination_port =
            u16::from_be_bytes([data[2], data[3]]);

        let sequence_number = u32::from_be_bytes([
            data[4], data[5], data[6], data[7],
        ]);

        let acknowledgement_number = u32::from_be_bytes([
            data[8], data[9], data[10], data[11],
        ]);

        let data_offset = (data[12] >> 4) * 4;

        let flags =
            u16::from_be_bytes([data[12] & 0x1F, data[13]]);

        let window_size =
            u16::from_be_bytes([data[14], data[15]]);

        let checksum =
            u16::from_be_bytes([data[16], data[17]]);

        let urgent_pointer =
            u16::from_be_bytes([data[18], data[19]]);

        if data.len() < data_offset as usize {
            return Err(
                "TCP header length exceeds packet size"
                    .to_string(),
            );
        }

        let payload = &data[data_offset as usize..];

        Ok(TcpPacket {
            source_port,
            destination_port,
            sequence_number,
            acknowledgement_number,
            data_offset,
            flags,
            window_size,
            checksum,
            urgent_pointer,
            payload,
        })
    }

    pub fn syn(&self) -> bool {
        self.flags & 0x002 != 0
    }

    pub fn ack(&self) -> bool {
        self.flags & 0x010 != 0
    }

    pub fn fin(&self) -> bool {
        self.flags & 0x001 != 0
    }
}