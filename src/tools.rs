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

//! Some useful tools when construting packet

use rand;
use rand::distributions::uniform::SampleUniform;
use rand::distributions::Distribution;
use rand::distributions::Standard;
use rand::prng::XorShiftRng;
use rand::rngs::EntropyRng;
use rand::Rng;
use rand::SeedableRng;
use std::net::Ipv4Addr;

/// A very fast but not secure guaranteed random number generator by using [Xorshift algorithm](https://en.wikipedia.org/wiki/Xorshift)
///
/// Same usage as `rand::random()`.
pub fn fast_random<T>() -> Result<T, rand::Error>
where
    T: PartialOrd + SampleUniform,
    Standard: Distribution<T>,
{
    let mut rng = XorShiftRng::from_rng(EntropyRng::new())?;
    Ok(rng.gen())
}

/// Generate random IPv4 address by calling `fast_random`
pub fn rand_ipv4() -> Result<Ipv4Addr, rand::Error> {
    Ok(Ipv4Addr::new(
        fast_random::<u8>()?,
        fast_random::<u8>()?,
        fast_random::<u8>()?,
        fast_random::<u8>()?,
    ))
}
