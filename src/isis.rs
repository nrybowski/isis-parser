use nom_derive::*;
use nom::combinator::complete;
use nom::multi::many0;
pub use nom::IResult;

use rusticata_macros::newtype_enum;

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, NomBE)]
pub struct IsisPacketType(pub u8);

newtype_enum! {
    impl display IsisPacketType {
        L2LinkStatePacket = 20,
    }
}

#[derive(Debug)]
pub enum IsisPacket {
    LinkStateProtocolDataUnit(IsisL2LinkStatePacket),
}

#[derive(NomBE)]
pub struct Irpd(u8);
impl std::fmt::Debug for Irpd {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{:#x}", self.0))
    }
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

#[derive(Nom)]
#[derive(Debug)]
#[nom(Selector(u8))]
pub enum IsisTlv {
    #[nom(Selector(22))]
    TlvExtendedIsReachability(IsisTlvExtendedIsReachability),
    #[nom(Selector(_), Ignore)]
    Unsupported
}

#[derive(Debug)]
pub enum IsisSubTlv {
    Unsupported    
}

#[derive(Debug, NomBE)]
pub struct IsisTlvHeader {
    pub tlv_type: u8,
    pub len: u8,
}

// TODO: Use generic type
fn parse_is_neighbors(len: u8) -> impl Fn(&[u8]) -> IResult<&[u8], Vec<IsNeighbor>> {
    move |input: &[u8]| {
        let (data, rem) = input.split_at(len.into());
        let (_, v) = many0(complete(IsNeighbor::parse))(data)?;
        Ok((rem, v))
    }
}

#[derive(Debug, NomBE)]
pub struct IsisTlvExtendedIsReachability {
    pub header: IsisTlvHeader,
    #[nom(Parse(parse_is_neighbors(header.len)))]
    pub neighbors: Vec<IsNeighbor>,
}

#[derive(Debug, NomBE)]
pub struct IsNeighbor {
    pub is_neighbor_id: [u8; 7],
    pub metric: [u8; 3],
    pub sub_tlvs_len: u8,
    // TODO: Handle SubTLVs
    #[nom(SkipBefore(sub_tlvs_len), Ignore)]
    pub sub_tlvs: Vec<IsisSubTlv>,
}

#[derive(PartialOrd, Ord, Eq, Hash, PartialEq, Clone, Copy, NomBE, Serialize)]
pub struct LspId(u64);
impl std::fmt::Debug for LspId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!(
            "{:04x}.{:04x}.{:04x}.{:02x}-{:02x}", 
            (self.0 >> 48) as u16,
            (self.0 >> 32) as u16,
            (self.0 >> 16) as u16,
            (self.0 >> 8) as u8,
            self.0 as u8,
        ))
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
    #[nom(Verify = "header.pkt_type == IsisPacketType::L2LinkStatePacket")]
    pub header: IsisPacketHeader,
    pub pdu_length: u16,
    pub remaining_life: u16,
    pub lsp_id: LspId,
    pub seq_no: SeqNo,
    pub checksum: Chksm,
    pub type_block: u8,
    // #[nom(Cond(pdu_length - 19 > 0))]
    pub tlvs: Vec<IsisTlv>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, NomBE)]
pub struct IsisTlvType(pub u8);

newtype_enum! {
    impl display IsisTlvType {
        ExtendedIsReachability = 22,
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, NomBE)]
pub struct IsisSubTlvType(pub u8);

newtype_enum! {
    impl display IsisSubTlvType {
    }
}
