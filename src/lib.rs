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

//! # lib_blaster
//! The backend of blaster (a SYN flood tool)
//!
//! This library is using `libpnet` framework. And it only supports Linux now.
//!  
//! It can send about 33079 packets per second, which is very fast. And it can do it with low CPU usage.

extern crate pnet_macros_support;
extern crate pnet_packet;
extern crate pnet_transport;
extern crate rand;

pub mod builder;
pub mod collector;
pub mod sender;
pub mod tools;
