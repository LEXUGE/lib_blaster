// Copyright 2018 LEXUGE
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

use super::builder::build_pkt;
use super::collector::Collector;
use pnet_packet::ip::IpNextHeaderProtocols::Tcp;
use pnet_transport::transport_channel;
use pnet_transport::TransportChannelType::Layer3;
use std::io;
use std::net::IpAddr;

pub fn send_syn(collector: &Collector) -> Result<(), io::Error> {
    let (mut tx, _) = transport_channel(100, Layer3(Tcp))?;
    let mut packet = [0u8; 40];
    let packet = build_pkt(collector, &mut packet)?;
    match tx.send_to(packet, IpAddr::V4(collector.dst_ip)) {
        Ok(_) => Ok(()),
        Err(e) => Err(e),
    }
}
