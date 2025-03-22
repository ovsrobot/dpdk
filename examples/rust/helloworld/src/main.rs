/// Usage: helloworld -a <port 1 params> -a <port 2 params> ...
use std::env;
use std::ffi::CStr;
use std::ffi::CString;
use std::os::raw::{c_char, c_int};

use dpdk::raw::rte_eal::{
    rte_eal_cleanup,
    // Functions
    rte_eal_init,
};

use dpdk::raw::rte_ethdev::{
    RTE_ETH_DEV_NO_OWNER,
    RTE_ETH_NAME_MAX_LEN,
    RTE_ETH_RSS_IP,
    rte_eth_conf,
    rte_eth_dev_configure,
    // Functions
    rte_eth_dev_get_name_by_port,
    // Structures
    rte_eth_dev_info,
    rte_eth_dev_info_get,
    rte_eth_dev_start,
    rte_eth_find_next_owned_by,
    rte_eth_rx_mq_mode_RTE_ETH_MQ_RX_RSS,
    rte_eth_rx_mq_mode_RTE_ETH_MQ_RX_VMDQ_DCB_RSS,

    rte_eth_rx_queue_setup,
    rte_eth_rxconf,

    rte_eth_tx_queue_setup,
    rte_eth_txconf,
};

use dpdk::raw::rte_build_config::RTE_MAX_ETHPORTS;

use dpdk::raw::rte_mbuf::rte_pktmbuf_pool_create;

use dpdk::raw::rte_mbuf_core::RTE_MBUF_DEFAULT_BUF_SIZE;

pub type DpdkPort = u16;
pub struct Port {
    pub port_id: DpdkPort,
    pub dev_info: rte_eth_dev_info,
    pub dev_conf: rte_eth_conf,
    pub rxq_num: u16,
    pub txq_num: u16,
}

impl Port {
    unsafe fn new(id: DpdkPort) -> Self {
        Port {
            port_id: id,
            dev_info: unsafe {
                let uninit: ::std::mem::MaybeUninit<rte_eth_dev_info> =
                    ::std::mem::MaybeUninit::zeroed().assume_init();
                *uninit.as_ptr()
            },
            dev_conf: unsafe {
                let uninit: ::std::mem::MaybeUninit<rte_eth_conf> =
                    ::std::mem::MaybeUninit::zeroed().assume_init();
                *uninit.as_ptr()
            },
            rxq_num: 1,
            txq_num: 1,
        }
    }

    pub unsafe fn init_port_config(&mut self) {
        let ret = unsafe {
            rte_eth_dev_info_get(self.port_id, &mut self.dev_info as *mut rte_eth_dev_info)
        };
        if ret != 0 {
            panic!("self-{}: failed to get dev info {ret}", self.port_id);
        }

        self.dev_conf.rx_adv_conf.rss_conf.rss_key = std::ptr::null_mut();
        self.dev_conf.rx_adv_conf.rss_conf.rss_hf = if self.rxq_num > 1 {
            RTE_ETH_RSS_IP as u64 & self.dev_info.flow_type_rss_offloads
        } else {
            0
        };

        if self.dev_conf.rx_adv_conf.rss_conf.rss_hf != 0 {
            self.dev_conf.rxmode.mq_mode = rte_eth_rx_mq_mode_RTE_ETH_MQ_RX_VMDQ_DCB_RSS
                & rte_eth_rx_mq_mode_RTE_ETH_MQ_RX_RSS;
        }
    }

    unsafe fn start_port(&mut self) {
        let mut rc = unsafe {
            rte_eth_dev_configure(
                self.port_id,
                self.rxq_num,
                self.txq_num,
                &self.dev_conf as *const rte_eth_conf,
            )
        };
        if rc != 0 {
            panic!("failed to configure self-{}: {rc}", self.port_id)
        }
        println!("self-{} configured", self.port_id);

        rc = unsafe { rte_eth_tx_queue_setup(self.port_id, 0, 64, 0, 0 as *const rte_eth_txconf) };
        if rc != 0 {
            panic!("self-{}: failed to configure TX queue 0 {rc}", self.port_id)
        }
        println!("self-{} configured TX queue 0", self.port_id);

        let mbuf_pool_name = CString::new(format!("mbuf pool self-{}", self.port_id)).unwrap();
        let mbuf_pool: *mut dpdk::raw::rte_mbuf::rte_mempool = unsafe {
            rte_pktmbuf_pool_create(
                mbuf_pool_name.as_ptr(),
                1024,
                0,
                0,
                RTE_MBUF_DEFAULT_BUF_SIZE as u16,
                0,
            )
        };
        if mbuf_pool == 0 as *mut dpdk::raw::rte_mbuf::rte_mempool {
            panic!("self-{}: failed to allocate mempool {rc}", self.port_id)
        }
        println!("self-{} mempool ready", self.port_id);

        let mut rxq_conf: rte_eth_rxconf = self.dev_info.default_rxconf.clone();
        rxq_conf.offloads = 0;
        rc = unsafe {
            rte_eth_rx_queue_setup(
                self.port_id,
                0,
                64,
                0,
                &mut rxq_conf as *mut rte_eth_rxconf,
                mbuf_pool as *mut dpdk::raw::rte_ethdev::rte_mempool,
            )
        };
        if rc != 0 {
            panic!("self-{}: failed to configure RX queue 0 {rc}", self.port_id)
        }
        println!("self-{} configured RX queue 0", self.port_id);
        rc = unsafe { rte_eth_dev_start(self.port_id) };
        if rc != 0 {
            panic!("failed to start self-{}: {rc}", self.port_id)
        }
        println!("self-{} started", self.port_id);
    }
}

pub unsafe fn iter_rte_eth_dev_owned_by(owner_id: u64) -> impl Iterator<Item = DpdkPort> {
    let mut port_id: DpdkPort = 0 as DpdkPort;
    std::iter::from_fn(move || {
        let cur = port_id;
        port_id = unsafe { rte_eth_find_next_owned_by(cur, owner_id) as DpdkPort };
        if port_id == RTE_MAX_ETHPORTS as DpdkPort {
            return None;
        }
        if cur == port_id {
            port_id += 1
        }
        Some(cur)
    })
}

pub unsafe fn iter_rte_eth_dev() -> impl Iterator<Item = DpdkPort> {
    unsafe { iter_rte_eth_dev_owned_by(RTE_ETH_DEV_NO_OWNER as u64) }
}

pub unsafe fn show_ports_summary(ports: &Vec<Port>) {
    let mut name_buf: [c_char; RTE_ETH_NAME_MAX_LEN as usize] =
        [0 as c_char; RTE_ETH_NAME_MAX_LEN as usize];
    let title = format!("{:<4}    {:<32} {:<14}", "Port", "Name", "Driver");
    println!("{title}");
    ports.iter().for_each(|p| unsafe {
        let _rc = rte_eth_dev_get_name_by_port(p.port_id, name_buf.as_mut_ptr());
        let name = CStr::from_ptr(name_buf.as_ptr());
        let drv = CStr::from_ptr(p.dev_info.driver_name);
        let summary = format!(
            "{:<4}    {:<32} {:<14}",
            p.port_id,
            name.to_str().unwrap(),
            drv.to_str().unwrap()
        );
        println!("{summary}");
    });
}

fn main() {
    let mut argv: Vec<*mut c_char> = env::args()
        .map(|arg| CString::new(arg).unwrap().into_raw())
        .collect();

    let rc = unsafe { rte_eal_init(env::args().len() as c_int, argv.as_mut_ptr()) };
    if rc == -1 {
        unsafe {
            rte_eal_cleanup();
        }
    }

    let mut ports: Vec<Port> = vec![];
    unsafe {
        for port_id in
            iter_rte_eth_dev().take(dpdk::raw::rte_build_config::RTE_MAX_ETHPORTS as usize)
        {
            let mut port = Port::new(port_id);
            port.init_port_config();
            println!("init port {port_id}");
            port.start_port();
            ports.push(port);
        }
    }

    unsafe {
        show_ports_summary(&ports);
    }

    println!("Hello, world!");
}
