extern crate lib_blaster;
#[macro_use]
extern crate criterion;

use criterion::Criterion;
use lib_blaster::builder::Pkt;
use lib_blaster::collector::Collector;
use lib_blaster::sender::Sender;
use lib_blaster::tools::{fast_random, rand_ipv4};
use std::net::Ipv4Addr;

fn send_1(c: &mut Criterion) {
    let mut packet = Pkt::new(&Collector {
        src_ip: Ipv4Addr::new(127, 0, 0, 1),
        dst_ip: Ipv4Addr::new(127, 0, 0, 1),
        src_port: 1,
        dst_port: 80,
    }).unwrap();
    let _sender = Sender::new().unwrap();
    c.bench_function("Send 1 packet", move |b| {
        b.iter(|| {
            packet.set_src_port(fast_random::<u16>().unwrap());
            packet.set_src_ip(rand_ipv4().unwrap());
        })
    });
}

criterion_group!(benches, send_1);
criterion_main!(benches);
