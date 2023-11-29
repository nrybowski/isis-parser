use nom::{
    combinator::{complete, peek},
    number::streaming::{be_u8},
    multi::many0,
    IResult
};

use rusticata_macros::newtype_enum;

use nom_derive::*;

use crate::{
    isis::skipper,
    subtlv::*,
};


#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, NomBE)]
pub struct IsisTlvType(pub u8);

newtype_enum! {
    impl display IsisTlvType {
        ExtendedIsReachability = 22,
    }
}

#[derive(Debug, NomBE)]
#[nom(Selector(IsisTlvType))]
pub enum IsisTlv {
    #[nom(Selector(IsisTlvType::ExtendedIsReachability))]
    TlvExtendedIsReachability(IsisTlvExtendedIsReachability),
    #[nom(Selector(_), Parse(skipper))]
    Unsupported,
}

#[derive(Debug, Clone, NomBE)]
pub struct IsisGenericTlvHeader<T> {
    pub tlv_type: T,
    pub len: u8,
}

type IsisTlvHeader = IsisGenericTlvHeader<IsisTlvType>;

/* ############
*  ### TLVs ###
*  ############
*/

#[derive(Debug, NomBE)]
pub struct IsisTlvExtendedIsReachability {
    #[nom(Verify(header.tlv_type == IsisTlvType::ExtendedIsReachability))]
    pub header: IsisTlvHeader,
    #[nom(Parse(parse_is_neighbors(header.len)))]
    pub neighbors: Vec<IsNeighbor>,
}

#[derive(Debug, NomBE, Clone)]
pub struct IsNeighbor {
    pub is_neighbor_id: [u8; 7],
    pub metric: [u8; 3],
    pub sub_tlvs_len: u8,
    #[nom(Cond(sub_tlvs_len > 0), Parse(parse_isis_subtlvs(sub_tlvs_len)))]
    pub sub_tlvs: Option<Vec<IsisSubTlv>>,
}

/* ########################
*  ### Specific parsers ###
*  ########################
*/

// TODO: Use generic types and merge with parse_isis_subtlvs
pub fn parse_isis_tlvs<'a>(len: u16) -> impl Fn(&'a[u8]) -> IResult<&'a[u8], Vec<IsisTlv>> {
    move |input: &'a[u8]| {
        let (data, rem) = input.split_at(len.into());
        let (_, v) = many0(complete(
            move |input: &'a[u8]| {
                let (_, t) = peek(be_u8)(input)?;
                IsisTlv::parse(input, IsisTlvType(t))
            }
        ))(data)?;
        Ok((rem, v))
    }
}

// TODO: Use generic type
pub fn parse_is_neighbors(len: u8) -> impl Fn(&[u8]) -> IResult<&[u8], Vec<IsNeighbor>> {
    move |input: &[u8]| {
        let (data, rem) = input.split_at(len.into());
        let (_, v) = many0(complete(IsNeighbor::parse))(data)?;
        Ok((rem, v))
    }
}
