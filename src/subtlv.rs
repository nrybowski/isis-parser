use nom::{
    number::streaming::{be_u8, be_u32},
    combinator::{complete, peek},
    multi::many0,
    IResult
};

use rusticata_macros::*;

use nom_derive::*;

use crate::tlv::IsisGenericTlvHeader;


#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, NomBE)]
pub struct IsisSubTlvType(pub u8);

newtype_enum! {
    impl display IsisSubTlvType {
        Ipv4NeighborAddress = 8,
        Ipv4InterfaceAddress = 6,
    }
}

type IsisSubTlvHeader = IsisGenericTlvHeader<IsisSubTlvType>;

#[derive(Debug, Clone, NomBE)]
#[nom(Selector(IsisSubTlvType))]
pub enum IsisSubTlv {
    #[nom(Selector(IsisSubTlvType::Ipv4InterfaceAddress))]
    Ipv4InterfaceAddress(IsisSubTlvIpv4InterfaceAddress),
    #[nom(Selector(IsisSubTlvType::Ipv4NeighborAddress))]
    Ipv4NeighborAddress(IsisSubTlvIpv4NeighborAddress),
    // TODO: use skipper
    #[nom(Selector(_), Ignore)]
    Unsupported    
}

/* ###############
*  ### SubTLVs ###
*  ###############
*/

#[derive(Debug, Clone, NomBE)]
pub struct IsisSubTlvIpv4InterfaceAddress {
    #[nom(Verify(header.tlv_type == IsisSubTlvType::Ipv4InterfaceAddress))]
    pub header: IsisSubTlvHeader,
    #[nom(Map(|a| std::net::Ipv4Addr::from(a)), Parse(be_u32))]
    pub addr: std::net::Ipv4Addr,
}

#[derive(Debug, Clone, NomBE)]
pub struct IsisSubTlvIpv4NeighborAddress {
    #[nom(Verify(header.tlv_type == IsisSubTlvType::Ipv4NeighborAddress))]
    pub header: IsisSubTlvHeader,
    #[nom(Map(|a| std::net::Ipv4Addr::from(a)), Parse(be_u32))]
    pub addr: std::net::Ipv4Addr,
}

/* ########################
*  ### Specific parsers ###
*  ########################
*/

pub fn parse_isis_subtlvs<'a>(len: u8) -> impl Fn(&'a[u8]) -> IResult<&'a[u8], Vec<IsisSubTlv>> {
    move |input: &'a[u8]| {
        let (data, rem) = input.split_at(len.into());
        let (_, v) = many0(complete(
            move |input: &'a[u8]| {
                let (_, t) = peek(be_u8)(input)?;
                IsisSubTlv::parse(input, IsisSubTlvType(t))
            }
        ))(data)?;
        Ok((rem, v))
    }
}
