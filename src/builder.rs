// Copyright 2018 LEXUGE
// This file is part of lib_blaster.

// lib_blaster is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// lib_blaster is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.

// You should have received a copy of the GNU Affero General Public License
// along with lib_blaster.  If not, see <https://www.gnu.org/licenses/>.

use super::collector::Collector;
use pnet_packet::ip::IpNextHeaderProtocols::Tcp;
use pnet_packet::ipv4::{checksum, Ipv4Flags, MutableIpv4Packet};
use pnet_packet::tcp::{ipv4_checksum, MutableTcpPacket, TcpFlags, TcpPacket};
use rand::random;
use std::io::{Error, ErrorKind};

pub fn build_pkt<'a>(collector: &Collector, packet: &'a mut [u8]) -> Result<TcpPacket<'a>, Error> {
    const IPV4_HEADER_LEN: usize = 20;
    {
        // construct IP header
        let mut ip_header = match MutableIpv4Packet::new(packet) {
            Some(s) => s,
            None => {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "Can't create `MutableIpv4Packet`.",
                ))
            }
        };
        ip_header.set_version(4);
        ip_header.set_header_length(5);
        // Miss: type of service
        // Miss: total length
        ip_header.set_identification(random::<u16>());
        ip_header.set_flags(Ipv4Flags::DontFragment);
        // Miss: fragment offset
        ip_header.set_ttl(128);
        ip_header.set_next_level_protocol(Tcp);
        ip_header.set_source(collector.src_ip);
        ip_header.set_destination(collector.dst_ip);
        let checksum = checksum(&ip_header.to_immutable());
        ip_header.set_checksum(checksum);
    }
    {
        // construct TCP header
        let mut tcp_header = match MutableTcpPacket::new(&mut packet[IPV4_HEADER_LEN..]) {
            Some(s) => s,
            None => {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "Can't create `MutableTcpPacket`.",
                ))
            }
        };
        tcp_header.set_source(collector.src_port);
        tcp_header.set_destination(collector.dst_port);
        tcp_header.set_sequence(random::<u32>());
        // Miss: ACK
        tcp_header.set_data_offset(5);
        // Miss: Reserved
        tcp_header.set_flags(TcpFlags::SYN);
        tcp_header.set_window(29200);
        tcp_header.set_urgent_ptr(0);
        let checksum = ipv4_checksum(
            &tcp_header.to_immutable(),
            &collector.src_ip,
            &collector.dst_ip,
        );
        tcp_header.set_checksum(checksum);
    }
    match TcpPacket::new(packet) {
        Some(s) => Ok(s),
        None => Err(Error::new(
            ErrorKind::InvalidData,
            "Can't create `TcpPacket`.",
        )),
    }
}
