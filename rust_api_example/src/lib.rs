// Outline for safe DPDK API bindings
//  - None of the APIs are actually implemented, this is API design only
//  - This demo runs 2x threads on 2x Rxqs, and cannot accidentally poll incorrectly

pub mod dpdk {
    pub mod eth {
        use super::Mempool;
        use std::sync::Arc;

        // PortHandle here is used as a refcount of "Outstanding Rx/Tx queues".
        // This is useful, but the "runstate" of the port is also useful. They are
        // similar, but not identical. A more elegant solution is likely possible.
        #[derive(Debug, Clone)]
        #[allow(unused)]
        pub(crate) struct PortHandle(Arc<()>);

        impl PortHandle {
            fn new() -> Self {
                PortHandle(Arc::new(()))
            }
            fn stop(&mut self) -> Result<(), usize> {
                // if the count is 1, only the Port itself has a handle left.
                // In that case, the count cannot go up, so we can stop.
                // The strange "Arc::<()>::function()" syntax here is "Fully qualified syntax":
                //  - https://doc.rust-lang.org/std/sync/struct.Arc.html#deref-behavior
                let sc = Arc::<()>::strong_count(&self.0);
                if  sc == 1 {
                    Ok(())
                } else {
                    Err(sc)
                }
            }
        }
        
        #[derive(Debug)]
        pub struct TxqHandle {/* todo: but same as Rxq */}

        // Handle allows moving between threads, its not polling!
        #[derive(Debug)]
        pub struct RxqHandle {
            _handle: PortHandle,
            port: u16,
            queue: u16,
        }

        impl RxqHandle {
            pub(crate) fn new(handle: PortHandle, port: u16, queue: u16) -> Self {
                RxqHandle { _handle: handle, port, queue }
            }

            // This function is the key to the API design: it ensures the rx_burst()
            // function is only available via the Rxq struct, after enable_polling() has been called.
            // It "consumes" (takes "self" as a parameter, not a '&' reference!) which essentially
            // destroys/invalidates the handle from the Application level code.

            // It returns an Rxq instance, which has the PhantomData to encode the threading requirements,
            // and the Rxq has the rx_burst() function: this allows the application to recieve packets.
            pub fn enable_polling(self) -> Rxq {
                Rxq {
                    handle: self,
                    _phantom: std::marker::PhantomData,
                }
            }
        }

        #[derive(Debug)]
        pub struct Rxq {
            handle: RxqHandle,
            // This "PhantomData" tells the rust compiler to Pretend the Rc<()> is in this struct
            // but in practice it is a Zero-Sized-Type, so takes up no space. It is a compile-time
            // language technique to ensure the struct is not moved between threads. This encodes
            // the API requirement "don't poll from multiple threads without synchronisation (e.g. Mutex)"
            _phantom: std::marker::PhantomData<std::rc::Rc<()>>,
        }

        impl Rxq {
            // TODO: datapath Error types should be lightweight, not String. Here we return ().
            pub fn rx_burst(&mut self, _mbufs: &mut [u8]) -> Result<usize, ()> {
                // TODO: Design the Mbuf struct wrapper, and how to best return a batch
                //  e.g.: investigate "ArrayVec" crate for safe & fixed sized, stack allocated arrays
                //
                // There is work to do here, but I want to communicate the general DPDK/EAL/Eth/Rxq concepts
                // now, this part is not done yet: it is likely the hardest/most performance critical.
                //
                // call rte_eth_rx_burst() here
                println!(
                    "[thread: {:?}] rx_burst: port {} queue {}",
                    std::thread::current().id(),
                    self.handle.port,
                    self.handle.queue
                );
                Ok(0)
            }
        }

        #[derive(Debug)]
        pub struct Port {
            handle: PortHandle,
            id: u16,
            rxqs: Vec<RxqHandle>,
            txqs: Vec<TxqHandle>,
        }

        impl Port {
            // pub(crate) here ensures outside this crate users cannot call this function
            pub(crate) fn from_u16(id: u16) -> Self {
                Port {
                    handle: PortHandle::new(),
                    id,
                    rxqs: Vec::new(),
                    txqs: Vec::new(),
                }
            }

            pub fn rxqs(&mut self, rxq_count: u16, _mempool: Mempool) -> Result<(), String> {
                // ensure no old ports remain
                self.rxqs.clear();

                for q in 0..rxq_count {
                    // call rte_eth_rx_queue_setup() here
                    self.rxqs.push(RxqHandle::new(self.handle.clone(), self.id, q));
                }
                println!("{:?}", self.handle);
                Ok(())
            }

            pub fn start(&mut self) -> (Vec<RxqHandle>, Vec<TxqHandle>) {
                // call rte_eth_dev_start() here, then give ownership of Rxq/Txq to app
                (
                    std::mem::take(&mut self.rxqs),
                    std::mem::take(&mut self.txqs),
                )
            }

            pub fn stop(&mut self) -> Result<(), String> {
                match self.handle.stop() {
                    Ok(_v) => {
                        // call rte_eth_dev_stop() here
                        println!("stopping port {}", self.id);
                        Ok(())
                    }
                    Err(e) => Err(format!("Port has {} Rxq/Txq handles outstanding", e)),
                }
            }
        }
    }

    #[derive(Debug, Clone)]
    // Mempool is a long-life object, which many other DPDK things refer to (e.g. rxq config)
    // Having a Rust lifetime attached to it (while technically correct) would complicate the
    // code a LOT, and for little value. This is a tradeoff - happy to discuss more if we want.
    // The choice here is to derive "Clone", allowing handing over multiple instances of the
    // same Mempool, similar to how Arc<Mempool> would work, but without the reference counting.
    pub struct Mempool {}

    impl Mempool {
        pub fn new(_size: usize) -> Self {
            Self {}
        }
    }

    #[derive(Debug)]
    pub struct Eal {
        eth_ports: Option<Vec<eth::Port>>,
    }

    impl Eal {
        //  allow init once,
        pub fn init() -> Result<Self, String> {
            // EAL init() will do PCI probe and VDev enumeration will find/create eth ports.
            // This code should loop over the ports, and build up Rust structs representing them
            let eth_port = vec![eth::Port::from_u16(0)];
            Ok(Eal {
                eth_ports: Some(eth_port),
            })
        }

        // API to get eth ports, taking ownership. It can be called once.
        // The return will be None for future calls
        pub fn take_eth_ports(&mut self) -> Option<Vec<eth::Port>> {
            self.eth_ports.take()
        }
    }

    impl Drop for Eal {
        fn drop(&mut self) {
            // todo: rte_eal_cleanup()
        }
    }
} // DPDK mod
