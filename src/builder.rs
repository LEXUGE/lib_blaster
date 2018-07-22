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

//! The packet builder

use super::collector::Collector;
use pnet_macros_support::packet::Packet;
use pnet_packet::ip::IpNextHeaderProtocols::Tcp;
use pnet_packet::ipv4::{checksum, Ipv4Flags, MutableIpv4Packet};
use pnet_packet::tcp::{ipv4_checksum, MutableTcpPacket, TcpFlags, TcpPacket};
use std::io::{Error, ErrorKind};
use std::net::Ipv4Addr;
use tools::fast_random;

/// The mutable packet container
pub struct Pkt<'a> {
    ipv4_pkt: MutableIpv4Packet<'a>,
    tcp_pkt: MutableTcpPacket<'a>,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
}

impl<'a> Pkt<'a> {
    /// Create a `Pkt` by providing `Collector`
    pub fn new(collector: &Collector) -> Result<Self, Error> {
        // construct IP header
        let mut ip_header = match MutableIpv4Packet::owned(vec![0u8; 20]) {
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
        ip_header.set_identification(match fast_random::<u16>() {
            Ok(s) => s,
            Err(_) => {
                return Err(Error::new(
                    ErrorKind::Other,
                    "Can't generate random number.",
                ))
            }
        });
        ip_header.set_flags(Ipv4Flags::DontFragment);
        // Miss: fragment offset
        ip_header.set_ttl(128);
        ip_header.set_next_level_protocol(Tcp);
        ip_header.set_source(collector.src_ip);
        ip_header.set_destination(collector.dst_ip);

        // construct TCP header
        let mut tcp_header = match MutableTcpPacket::owned(vec![0u8; 20]) {
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
        tcp_header.set_sequence(match fast_random::<u32>() {
            Ok(s) => s,
            Err(_) => {
                return Err(Error::new(
                    ErrorKind::Other,
                    "Can't generate random number.",
                ))
            }
        });
        // Miss: ACK
        tcp_header.set_data_offset(5);
        // Miss: Reserved
        tcp_header.set_flags(TcpFlags::SYN);
        tcp_header.set_window(29200);
        tcp_header.set_urgent_ptr(0);

        do_checksum(
            &mut ip_header,
            &mut tcp_header,
            collector.src_ip,
            collector.dst_ip,
        );
        Ok(Self {
            ipv4_pkt: ip_header,
            tcp_pkt: tcp_header,
            dst_ip: collector.dst_ip,
            src_ip: collector.src_ip,
        })
    }

    /// Convert `Pkt` to a immutable `TcpPacket`
    pub fn to_one_packet(&self) -> Result<TcpPacket, Error> {
        let mut v1 = (*self.ipv4_pkt.packet()).to_vec();
        let mut v2 = (*self.tcp_pkt.packet()).to_vec();
        v1.append(&mut v2);
        match TcpPacket::owned(v1) {
            Some(s) => Ok(s),
            None => Err(Error::new(
                ErrorKind::InvalidData,
                "Can't create `TcpPacket`.",
            )),
        }
    }

    /// set the source IP address of IP header
    pub fn set_src_ip(&mut self, src_ip: Ipv4Addr) {
        self.src_ip = src_ip;
        self.ipv4_pkt.set_source(self.src_ip);
        do_checksum(&mut self.ipv4_pkt, &mut self.tcp_pkt, src_ip, self.dst_ip);
    }

    /// set the source port of TCP header
    pub fn set_src_port(&mut self, src_port: u16) {
        self.tcp_pkt.set_source(src_port);
        do_checksum(
            &mut self.ipv4_pkt,
            &mut self.tcp_pkt,
            self.src_ip,
            self.dst_ip,
        );
    }

    /// Get the destination IP address
    pub fn get_dst_ip(&self) -> Ipv4Addr {
        self.dst_ip
    }
}

fn do_checksum(
    ip_header: &mut MutableIpv4Packet,
    tcp_header: &mut MutableTcpPacket,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
) {
    let checksum = checksum(&ip_header.to_immutable());
    ip_header.set_checksum(checksum);
    let checksum = ipv4_checksum(&tcp_header.to_immutable(), &src_ip, &dst_ip);
    tcp_header.set_checksum(checksum);
}
