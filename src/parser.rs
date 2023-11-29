use nom::combinator::{map, peek};
use nom::error::{make_error, ErrorKind};
use nom::number::streaming::{be_u64};
// use nom::bytes::streaming::take;
use nom_derive::Parse;
pub use nom::IResult;

use crate::isis::*;

pub fn parse_isis_packet(input: &[u8]) -> IResult<&[u8], IsisPacket> {
    let (_, word) = peek(be_u64)(input)?;

    let irpd = (word >> 56) as u8;
    if irpd != 0x83 {
        return Err(nom::Err::Error(make_error(input, ErrorKind::Tag)));
    }

    let pkt_type = ((word >> 24) as u8) & 0x1f;

    match IsisPacketType(pkt_type) {
        IsisPacketType::L2LinkStatePacket => map(IsisL2LinkStatePacket::parse, IsisPacket::LinkStateProtocolDataUnit)(input),
        _ => todo!(),
    }
}

#[cfg(test)]
mod test {
    use crate::*;

    #[test]
    fn parse_isis_hdr () {
        let isis_hdr = [0x83, 0x1b, 0x01, 0x00, 0x14, 0x01, 0x00, 0x00, 0x00, 0x33, 0xff, 0xf6,
                         0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x00, 0x00, 0x00, 0x00, 0x0a,
                         0xff, 0xff, 0x03, 0x16, 0x16, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x35,
                         0x00, 0x00, 0x00, 0x00, 0x12, 0x34, 0x56, 0x78, 0x90, 0x33, 0x00, 0x00,
                         0x00, 0x00, 0x00];
        let res = parse_isis_packet(&isis_hdr);
        match res {
            Ok((rem, _parsed)) => {
                assert!(rem.len() == 0);
                // TODO: Check parsed fields
            },
            _ => assert!(false),
        }

    }
}
