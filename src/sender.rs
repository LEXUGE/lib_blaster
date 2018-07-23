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

//! The packet sender

use super::builder::Pkt;
use pnet_packet::ip::IpNextHeaderProtocols::Tcp;
use pnet_transport;
use pnet_transport::transport_channel;
use pnet_transport::TransportChannelType::Layer3;
use std::io;
use std::net::IpAddr;

/// A Sender struct which contains Layer3 channel
pub struct Sender {
    tx: pnet_transport::TransportSender,
}

impl Sender {
    /// Create a sender
    pub fn new() -> Result<Self, io::Error> {
        let (tx, _) = transport_channel(100, Layer3(Tcp))?;
        Ok(Self { tx })
    }

    /// Send the SYN packets
    pub fn send_syn(&mut self, packet: &Pkt) -> Result<(), io::Error> {
        match self.tx
            .send_to(packet.to_one_packet()?, IpAddr::V4(packet.get_dst_ip()))
        {
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        }
    }
}
