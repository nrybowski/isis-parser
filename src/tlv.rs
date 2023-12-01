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

impl PartialEq for IsNeighbor {
    fn eq(&self, other: &Self) -> bool {
        if self.is_neighbor_id != other.is_neighbor_id || self.metric != other.metric { return false; }
        if self.sub_tlvs.is_none() && other.sub_tlvs.is_none() { return true; }
        else if let Some(self_tlvs) = &self.sub_tlvs && let Some(other_tlvs) = &other.sub_tlvs {
            // Ignore the Neighbor address as it does not imply that the link changed
            let self_ifaces: Vec<&IsisSubTlvIpv4InterfaceAddress> = self_tlvs.iter().filter_map(|e|
                if let IsisSubTlv::Ipv4InterfaceAddress(tlv) = e { Some(tlv) } else {None}    
            ).collect();
            let other_ifaces: Vec<&IsisSubTlvIpv4InterfaceAddress> = other_tlvs.iter().filter_map(|e|
                if let IsisSubTlv::Ipv4InterfaceAddress(tlv) = e { Some(tlv) } else {None}    
            ).collect();
            let l = self_ifaces.len();
            if l == other_ifaces.len() && l == 1 {
                return self_ifaces[0].addr == other_ifaces[0].addr;
            }
        }
        false
    }
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

/* #############
*  ### Tests ###
*  #############
*/

// TODO: Test parsing functions

#[cfg(test)]
mod isneighbor_equality {
    use crate::*;
    use nom_derive::Parse;

    /*
    * IsNeighbor: IS id (7 bytes), metric (3 bytes), sub tlvs len (1 byte) [subtlvs]
    */
    
    #[test]
    fn same_nid_same_metric_no_subtlvs() {
        let raw_n1 = [0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x00, 0x00, 0x01, 0x00];
        let (_, n1) = IsNeighbor::parse(&raw_n1).unwrap();
        let n2 = n1.clone();
        assert!(n1 == n2);
    }

    #[test]
    fn same_nid_different_metric_no_subtlvs() {
        let raw_n1 = [0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x00, 0x00, 0x01, 0x00];
        let raw_n2 = [0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x00, 0x00, 0x02, 0x00];
        let (_, n1) = IsNeighbor::parse(&raw_n1).unwrap();
        let (_, n2) = IsNeighbor::parse(&raw_n2).unwrap();
        assert!(n1 != n2);
    }

    
    #[test]
    fn different_nid_same_metric_no_subtlvs() {
        let raw_n1 = [0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x00, 0x00, 0x01, 0x00];
        let raw_n2 = [0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x31, 0x00, 0x00, 0x01, 0x00];
        let (_, n1) = IsNeighbor::parse(&raw_n1).unwrap();
        let (_, n2) = IsNeighbor::parse(&raw_n2).unwrap();
        assert!(n1 != n2);
    }

    #[test]
    fn different_nid_different_metric_no_subtlvs() {
        let raw_n1 = [0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x00, 0x00, 0x01, 0x00];
        let raw_n2 = [0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x31, 0x00, 0x00, 0x02, 0x00];
        let (_, n1) = IsNeighbor::parse(&raw_n1).unwrap();
        let (_, n2) = IsNeighbor::parse(&raw_n2).unwrap();
        assert!(n1 != n2);
    }
    
    #[test]
    fn same_nid_same_metric_same_v4interface_no_v4neighbor() {
        let raw_n1 = [0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x00, 0x00, 0x01, 0x06,
            0x6, 0x4, 0xc0, 0xa8, 0x0, 0x0
        ];
        let (_, n1) = IsNeighbor::parse(&raw_n1).unwrap();
        let n2 = n1.clone();
        assert!(n1 == n2);
    }

    #[test]
    fn same_nid_same_metric_different_v4interface_no_v4neighbor() {
        let raw_n1 = [0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x00, 0x00, 0x01, 0x06,
            0x6, 0x4, 0xc0, 0xa8, 0x0, 0x0
        ];
        let raw_n2 = [0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x00, 0x00, 0x01, 0x06,
            0x6, 0x4, 0xc0, 0xa8, 0x0, 0x1
        ];
        let (_, n1) = IsNeighbor::parse(&raw_n1).unwrap();
        let (_, n2) = IsNeighbor::parse(&raw_n2).unwrap();
        assert!(n1 != n2);
    }

    #[test]
    fn same_nid_different_metric_same_v4interface_no_v4neighbor() {
        let raw_n1 = [0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x00, 0x00, 0x01, 0x06,
            0x6, 0x4, 0xc0, 0xa8, 0x0, 0x0
        ];
        let raw_n2 = [0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x00, 0x00, 0x02, 0x06,
            0x6, 0x4, 0xc0, 0xa8, 0x0, 0x0
        ];
        let (_, n1) = IsNeighbor::parse(&raw_n1).unwrap();
        let (_, n2) = IsNeighbor::parse(&raw_n2).unwrap();
        assert!(n1 != n2);
    }

    
    #[test]
    fn same_nid_different_metric_different_v4interface_no_v4neighbor() {
        let raw_n1 = [0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x00, 0x00, 0x01, 0x06,
            0x6, 0x4, 0xc0, 0xa8, 0x0, 0x0
        ];
        let raw_n2 = [0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x00, 0x00, 0x02, 0x06,
            0x6, 0x4, 0xc0, 0xa8, 0x0, 0x1
        ];
        let (_, n1) = IsNeighbor::parse(&raw_n1).unwrap();
        let (_, n2) = IsNeighbor::parse(&raw_n2).unwrap();
        assert!(n1 != n2);
    }

    #[test]
    fn different_nid_different_metric_same_v4interface_no_v4neighbor() {
        let raw_n1 = [0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x00, 0x00, 0x01, 0x06,
            0x6, 0x4, 0xc0, 0xa8, 0x0, 0x0
        ];
        let raw_n2 = [0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x31, 0x00, 0x00, 0x02, 0x06,
            0x6, 0x4, 0xc0, 0xa8, 0x0, 0x0
        ];
        let (_, n1) = IsNeighbor::parse(&raw_n1).unwrap();
        let (_, n2) = IsNeighbor::parse(&raw_n2).unwrap();
        assert!(n1 != n2);
    }

    
    #[test]
    fn different_nid_different_metric_different_v4interface_no_v4neighbor() {
        let raw_n1 = [0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x00, 0x00, 0x01, 0x06,
            0x6, 0x4, 0xc0, 0xa8, 0x0, 0x0
        ];
        let raw_n2 = [0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x31, 0x00, 0x00, 0x02, 0x06,
            0x6, 0x4, 0xc0, 0xa8, 0x0, 0x1
        ];
        let (_, n1) = IsNeighbor::parse(&raw_n1).unwrap();
        let (_, n2) = IsNeighbor::parse(&raw_n2).unwrap();
        assert!(n1 != n2);
    }

    // TODO: test with v4 neighbor subtlv
}
