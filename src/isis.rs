use nom_derive::*;
use nom::error::{make_error, ErrorKind, Error};
use nom::number::streaming::{be_u8, be_u16, be_u32};
use nom::combinator::{complete, peek};
use nom::bytes::streaming::take;
use nom::multi::many0;
pub use nom::IResult;

use rusticata_macros::newtype_enum;

use serde::Serialize;

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

fn skipper(input: &[u8]) -> IResult<&[u8], IsisTlv> {
        let (_, hdr) = peek(be_u16)(input)?;
        let len = hdr as u8;
        let (rem, _skipped) = take::<u8, &[u8], Error<&[u8]>>((len+2) as u8)(input)?;    
        Ok((rem, IsisTlv::Unsupported))
}

#[derive(Debug, NomBE)]
#[nom(Selector(IsisTlvType))]
pub enum IsisTlv {
    #[nom(Selector(IsisTlvType::ExtendedIsReachability))]
    TlvExtendedIsReachability(IsisTlvExtendedIsReachability),
    #[nom(Selector(_), Parse(skipper))]
    Unsupported,
}

fn parse_isis_tlvs<'a>(len: u16) -> impl Fn(&'a[u8]) -> IResult<&'a[u8], Vec<IsisTlv>> {
    // println!("Called");
    move |input: &'a[u8]| {
        // println!("TlvS parse {:#x?} {} {}", input, len, input.len());
        let (data, rem) = input.split_at(len.into());
        let (_, v) = many0(complete(
            move |input: &'a[u8]| {
                // println!("Tlv parse {:#x?}", input);
                let (_, t) = peek(be_u8)(input)?;
                let t = IsisTlvType(t);
                // println!("{:#?}", t);
                IsisTlv::parse(input, t)
            }
        ))(data)?;
        Ok((rem, v))
    }
}
#[derive(Debug, Clone, NomBE)]
pub struct IsisSubTlvIpv4InterfaceAddress {
    #[nom(Verify = "header.tlv_type == 6")]
    pub header: IsisTlvHeader,
    #[nom(Map(|a| std::net::Ipv4Addr::from(a)), Parse(be_u32))]
    pub addr: std::net::Ipv4Addr,
}

#[derive(Debug, Clone, NomBE)]
pub struct IsisSubTlvIpv4NeighborAddress {
    #[nom(Verify = "header.tlv_type == 8")]
    pub header: IsisTlvHeader,
    #[nom(Map(|a| std::net::Ipv4Addr::from(a)), Parse(be_u32))]
    pub addr: std::net::Ipv4Addr,
}

#[derive(Debug, Clone, NomBE)]
#[nom(Selector(IsisSubTlvType))]
pub enum IsisSubTlv {
    #[nom(Selector(IsisSubTlvType::Ipv4InterfaceAddress))]
    Ipv4InterfaceAddress(IsisSubTlvIpv4InterfaceAddress),
    #[nom(Selector(IsisSubTlvType::Ipv4NeighborAddress))]
    Ipv4NeighborAddress(IsisSubTlvIpv4NeighborAddress),
    #[nom(Selector(_), Ignore)]
    Unsupported    
}

#[derive(Debug, Clone, NomBE)]
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
    #[nom(Verify = "header.tlv_type == 22")]
    pub header: IsisTlvHeader,
    #[nom(Parse(parse_is_neighbors(header.len)))]
    pub neighbors: Vec<IsNeighbor>,
}

// IsisSubTlv::parse(input: &[u8], selector: u8) -> IResult<&[u8], IsisSubTlv>

fn parse_isis_subtlvs<'a>(len: u8) -> impl Fn(&'a[u8]) -> IResult<&'a[u8], Vec<IsisSubTlv>> {
    move |input: &'a[u8]| {
        let (data, rem) = input.split_at(len.into());
        // println!("SubTlvS parse {:#x?}", input);
        let (_, v) = many0(complete(
            move |input: &'a[u8]| {
                // println!("SubTlv parse {:#x?}", input);
                let (_, t) = peek(be_u8)(input)?;
                let t = IsisSubTlvType(t);
                // println!("{:#?}", t);
                IsisSubTlv::parse(input, t)
            }
        ))(data)?;
        Ok((rem, v))
    }
}

#[derive(Debug, NomBE, Clone)]
pub struct IsNeighbor {
    pub is_neighbor_id: [u8; 7],
    pub metric: [u8; 3],
    pub sub_tlvs_len: u8,
    // TODO: Handle SubTLVs
    //#[nom(SkipBefore(sub_tlvs_len), Ignore)]
    #[nom(Cond(sub_tlvs_len > 0), Parse(parse_isis_subtlvs(sub_tlvs_len)))]
    pub sub_tlvs: Option<Vec<IsisSubTlv>>,
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
    #[nom(Cond(pdu_length - 27 > 0), Parse(parse_isis_tlvs(pdu_length - 27)))]
    pub tlvs: Option<Vec<IsisTlv>>,
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
        Ipv4NeighborAddress = 8,
        Ipv4InterfaceAddress = 6,
    }
}
