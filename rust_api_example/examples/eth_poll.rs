// Examples should not require any "unsafe" code.
#![deny(unsafe_code)]

use rust_api_example::dpdk::{self};

fn main() {
    let mut dpdk = dpdk::Eal::init().expect("dpdk must init ok");
    let rx_mempool = dpdk::Mempool::new(4096);

    let mut ports = dpdk.take_eth_ports().expect("take eth ports ok");
    let mut p = ports.pop().unwrap();

    p.rxqs(2, rx_mempool).expect("rxqs setup ok");
    println!("{:?}", p);

    let (mut rxqs, _txqs) = p.start();
    println!("rxqs: {:?}", rxqs);

    let rxq1 = rxqs.pop().unwrap();
    let rxq2 = rxqs.pop().unwrap();

    std::thread::spawn(move || {
        let mut rxq = rxq1.enable_polling();
        loop {
            let _nb_mbufs = rxq.rx_burst(&mut [0; 32]);
            std::thread::sleep(std::time::Duration::from_millis(1000));
        }
    });

    let mut rxq = rxq2.enable_polling();
    loop {
        let _nb_mbufs = rxq.rx_burst(&mut [0; 32]);
        std::thread::sleep(std::time::Duration::from_millis(1000));
    }
}