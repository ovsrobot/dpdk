// Examples should not require any "unsafe" code.
#![deny(unsafe_code)]

use rust_api_example::dpdk::{self};

fn main() {
    let mut dpdk = dpdk::Eal::init().expect("dpdk must init ok");
    let rx_mempool = dpdk::Mempool::new(4096);

    let mut ports = dpdk.take_eth_ports().expect("take eth ports ok");
    let mut p = ports.pop().unwrap();

    p.rxqs(2, rx_mempool.clone()).expect("rxqs setup ok");
    println!("{:?}", p);

    let (mut rxqs, _txqs) = p.start();
    println!("rxqs: {:?}", rxqs);

    let rxq1 = rxqs.pop().unwrap();
    let rxq2 = rxqs.pop().unwrap();

    std::thread::spawn(move || {
        let mut rxq = rxq1.enable_polling();
        for _ in 0..3 {
            let _nb_mbufs = rxq.rx_burst(&mut [0; 32]);
            std::thread::sleep(std::time::Duration::from_millis(1000));
        }
    });

    // "shadowing" variables is a common pattern in Rust, and is used here to
    // allow us to use the same variable name but for Rxq instead of RxqHandle.
    let mut rxq2 = rxq2.enable_polling();
    for _ in 0..2 {
        let _nb_mbufs = rxq2.rx_burst(&mut [0; 32]);
        std::thread::sleep(std::time::Duration::from_millis(1000));
    }

    // Important! As Port::stop() relies on RxqHandle's being dropped to
    // reduce the refcount, if the rxq is NOT dropped, it will NOT allow
    // the port to be stopped. This is actually a win for Safety (no polling stopped NIC ports)
    // but also a potential bug/hiccup at application code level.
    // Uncomment this line to see the loop below stall forever (waiting for Arc ref count to drop from 2 to 1)
    drop(rxq2);

    loop {
        let r = p.stop();
        match r {
            Ok(_v) => {
                println!("stopping port");
                break;
            }
            Err(e) => {
                println!("stop() returns error: {}", e);
            }
        };
        std::thread::sleep(std::time::Duration::from_millis(300));
    }

    // Reconfigure after stop()
    p.rxqs(4, rx_mempool.clone()).expect("rxqs setup ok");
    println!("{:?}", p);

    // queues is a tuple of (rxqs, txqs) here
    let queues = p.start();
    println!("queues: {:?}", queues);
    drop(queues);

    p.stop().expect("stop() ok");
    println!("stopped port");
}