#[derive(Debug)]
pub struct EthernetFrame<'a> {
    pub destination_mac: [u8; 6],
    pub source_mac: [u8; 6],
    pub ethertype: u16,
    pub payload: &'a [u8],
}

impl<'a> EthernetFrame<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self, String> {
        if data.len() < 14 {
            return Err("Ethernet frame too short".to_string());
        }

        let destination_mac = data[0..6]
            .try_into()
            .map_err(|_| "Invalid destination MAC")?;

        let source_mac = data[6..12]
            .try_into()
            .map_err(|_| "Invalid source MAC")?;

        let ethertype = u16::from_be_bytes([data[12], data[13]]);
        let payload = &data[14..];

        Ok(EthernetFrame {
            destination_mac,
            source_mac,
            ethertype,
            payload,
        })
    }

    pub fn format_mac(mac: &[u8; 6]) -> String {
        format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
        )
    }
}