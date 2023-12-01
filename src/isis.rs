use nom_derive::*;
use nom::error::{Error};
use nom::number::streaming::{be_u16};
use nom::combinator::{peek};
use nom::bytes::streaming::take;
pub use nom::IResult;

use rusticata_macros::newtype_enum;
use crate::tlv::*;

use serde::Serialize;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, NomBE)]
pub struct IsisPacketType(pub u8);

newtype_enum! {
    impl display IsisPacketType {
        L2LinkStatePacket = 20,
    }
}

// TODO: Use nom Selector
#[derive(Debug)]
pub enum IsisPacket {
    LinkStateProtocolDataUnit(IsisL2LinkStatePacket),
}

#[derive(Debug, NomBE)]
pub struct IsisPacketHeader {
    pub irpd: Irpd,
    pub len: u8,
    pub version: u8,
    pub sysid_len: u8,
    pub pkt_type: IsisPacketType,
    pub version2: u8,
    pub reserved: u8,
    pub max_area_adr: u8
}

pub fn skipper(input: &[u8]) -> IResult<&[u8], IsisTlv> {
    // let (_, hdr) = peek(be_u16)(input)?;
    let (input, hdr) = take(2 as usize)(input)?;
    let len = hdr[1];
    // let (rem, _skipped) = take::<u8, &[u8], Error<&[u8]>>((len+2) as u8)(input)?;    
    let (rem, _skipped) = take::<u8, &[u8], Error<&[u8]>>((len) as u8)(input)?;    
    Ok((rem, IsisTlv::Unsupported))
}

#[derive(PartialOrd, Ord, Eq, Hash, PartialEq, Clone, Copy, NomBE, Serialize)]
pub struct LspId{
    pub system_id: [u16;3],
    pub pseudo_id: u8,
    pub frag_id: u8,
}

impl std::fmt::Debug for LspId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!(
            "{:04x}.{:04x}.{:04x}.{:02x}-{:02x}", 
            self.system_id[0],
            self.system_id[1],
            self.system_id[2],
            self.pseudo_id,
            self.frag_id,
        ))
    }
}

#[derive(NomBE)]
pub struct Irpd(u8);
impl std::fmt::Debug for Irpd {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{:#x}", self.0))
    }
}

#[derive(NomBE)]
pub struct SeqNo(u32);
impl std::fmt::Debug for SeqNo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("0x{:08x}", self.0))
    }
}

#[derive(NomBE)]
pub struct Chksm(u16);
impl std::fmt::Debug for Chksm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("0x{:04x}", self.0))
    }
}

#[derive(Debug, NomBE)]
pub struct IsisL2LinkStatePacket {
    #[nom(Verify(header.pkt_type == IsisPacketType::L2LinkStatePacket))]
    pub header: IsisPacketHeader,
    pub pdu_length: u16,
    pub remaining_life: u16,
    pub lsp_id: LspId,
    pub seq_no: SeqNo,
    pub checksum: Chksm,
    pub type_block: u8,
    #[nom(Cond(pdu_length - 27 > 0), Parse(parse_isis_tlvs(pdu_length - 27)))]
    pub tlvs: Option<Vec<IsisTlv>>,
}
