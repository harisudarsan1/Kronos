#![no_std]
#![no_main]

use aya_ebpf::{
    // bindings::task_struct,
    bpf_printk,
    helpers::{
        self, bpf_get_current_ancestor_cgroup_id, bpf_get_current_cgroup_id, bpf_get_current_comm,
        bpf_get_current_task_btf, bpf_probe_read_kernel_buf, bpf_skb_load_bytes,
    },
    macros::{cgroup_skb, lsm, map},
    maps::{lpm_trie::Key, BloomFilter, HashMap, LpmTrie},
    programs::{LsmContext, SkBuffContext},
    EbpfContext,
};
use aya_log_ebpf::info;

use kronos_ebpf::{
    djb2_hash, djb2_hash_dns, djb2_hash_from_str, getnamehashfromfilestruct, vmlinux,
};

use kronos_common::{
    BinaryAllowMap, BinaryMap, FileMap, NRule, NetworkAllowValue, NetworkRule, PodBpfMap,
};

use network_types::{
    ip::Ipv4Hdr,
    tcp::{TcpHdr, TCP_HDR_LEN},
    udp::UdpHdr,
};
use vmlinux::{iphdr, task_struct};

#[repr(C)]
#[derive(Copy, Clone)]
struct DnsHdr {
    transaction_id: u16,
    flags: u16,
    qdcount: u16,
    ancount: u16,
    nscount: u16,
    arcount: u16,
}

#[repr(C)]
#[derive(Copy, Clone)]
enum NetworkTargets {
    TCP,
    UDP,
    DNS,
}

#[map]
static KRONOS_PODS: HashMap<u64, PodBpfMap> = HashMap::with_max_entries(1024, 0);

/*
maps for File target
 */
// TODO: Change the keys to struct type to avoid hash colliions
#[map]
static KRONOS_FILE_MAP: HashMap<u64, FileMap> = HashMap::with_max_entries(1024, 0);

#[map]
static KRONOS_SOURCE_MAP: HashMap<u64, u32> = HashMap::with_max_entries(1024, 0);

// #[map]
// static file_bloom_filter: BloomFilter<u32> = BloomFilter::with_max_entries(1024, 0);
/*
maps for Binary target
 */

#[map]
static KRONOS_ALLOW_BINARY_MAP: HashMap<u64, BinaryAllowMap> = HashMap::with_max_entries(1024, 0);

#[map]
static KRONOS_BINARY_MAP: HashMap<u64, u8> = HashMap::with_max_entries(1024, 0);

/*
maps for Network target
 */

#[map]
static KRONOS_NETWORK_MAP: HashMap<u64, NRule> = HashMap::with_max_entries(1024, 0);

#[map]
static KRONOS_ALLOW_NETWORK_MAP: HashMap<u64, NetworkAllowValue> =
    HashMap::with_max_entries(1024, 0);

// #[lsm(hook = "socket_connect")]
// pub fn task_setnice(ctx: LsmContext) -> i32 {
//     match try_task_setnice(ctx) {
//         Ok(ret) => ret,
//         Err(ret) => ret,
//     }
// }
//
// fn try_task_setnice(ctx: LsmContext) -> Result<i32, i32> {
//     info!(&ctx, "lsm hook socket_connect called");
//     Ok(0)
// }

#[cgroup_skb]
pub fn cskb_igress(ctx: SkBuffContext) -> i32 {
    match unsafe { try_cskb(ctx, -1) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[cgroup_skb]
pub fn cskb(ctx: SkBuffContext) -> i32 {
    match unsafe { try_cskb(ctx, 1) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

const AF_INET: u32 = 2;
const AF_INET6: u16 = 10;
const ETH_P_IP: u32 = 8;
unsafe fn try_cskb(ctx: SkBuffContext, direction: i8) -> Result<i32, i32> {
    // Egress only checks the destination ports and IP's
    let protocol = unsafe { (*ctx.skb.skb).protocol };
    let skb = unsafe { *ctx.skb.skb };
    // let daddr = unsafe { (*ctx.skb.skb).remote_ip4 };
    if protocol != ETH_P_IP {
        return Ok(1);
    }

    let cgroupid = unsafe { bpf_get_current_ancestor_cgroup_id(3) };
    // pass the function if the id cant be retrieved as the return value 0 indicates thaat cgroupid can't be retrieved
    if cgroupid == 0 {
        return Ok(0);
    }
    if let Some(pod_bpf_map) = KRONOS_PODS.get(&cgroupid) {
        if (pod_bpf_map.target & 3) != 0 {
            match skb.family {
                AF_INET => {
                    let src_addr = u32::from_be(unsafe { skb.local_ip4 });

                    let dest_addr = u32::from_be(unsafe { skb.remote_ip4 });
                    let dport = u32::from_be(unsafe { skb.remote_port });

                    // Ensure we can access the packet data
                    let data = skb.data as usize;
                    let data_end = skb.data_end as usize;

                    let trans_layer_start = data + core::mem::size_of::<iphdr>();
                    // Ensure the IP header is within bounds
                    if data + core::mem::size_of::<iphdr>() > data_end {
                        return Ok(0); // Drop if bounds are invalid
                    }
                    let iph: *const iphdr = skb.data as *const iphdr;
                    let protocol = unsafe { (*iph).protocol };

                    info!(
                        &ctx,
                        "AF_INET src address: {:i}, dest address: {:i}  with port{} with proto{}",
                        src_addr,
                        dest_addr,
                        dport,
                        protocol
                    );

                    let label_namespace_key = pod_bpf_map.namespace_hash as u64;
                    match protocol {
                        6 => {
                            // Handle TCP rules
                            if trans_layer_start + core::mem::size_of::<TcpHdr>() > data_end {
                                return Ok(0); // Drop if bounds are invalid
                            }
                            let tcphdr: *const TcpHdr = trans_layer_start as *const TcpHdr;
                            let des = u16::from_be(unsafe { (*tcphdr).dest });
                            // info!(&ctx, "destport{}", des);

                            let hash = des as u64 ^ label_namespace_key;

                            if let Some(value) = KRONOS_ALLOW_NETWORK_MAP.get(&label_namespace_key)
                            {
                                if let NetworkAllowValue::LNValue { dns, udp, tcp } = value {
                                    let count = tcp.count;
                                    let action = tcp.action;

                                    // Handle "only allow" logic
                                    if count > 0 {
                                        return handle_net_allow(hash, action, direction);
                                    }
                                }
                            }

                            // Check fallback UDP map when not in "only allow"
                            return handle_net(hash, direction);
                        }
                        17 => {
                            if trans_layer_start + core::mem::size_of::<UdpHdr>() > data_end {
                                return Ok(0); // Drop if bounds are invalid
                            }

                            let udphdr: *const UdpHdr = trans_layer_start as *const UdpHdr;
                            let des = u16::from_be(unsafe { (*udphdr).dest });

                            match des {
                                53 | 5353 => {
                                    // check for DNS rules
                                    let dns_start =
                                        trans_layer_start + core::mem::size_of::<UdpHdr>();

                                    // Check bounds for DNS header
                                    if dns_start + core::mem::size_of::<DnsHdr>() > data_end {
                                        return Ok(0); // Invalid bounds
                                    }

                                    // Parse DNS header
                                    let dns_hdr: *const DnsHdr = dns_start as *const DnsHdr;

                                    // Ensure we can read the Question Count (qdcount)
                                    let qdcount = u16::from_be(unsafe { (*dns_hdr).qdcount });
                                    if qdcount == 0 {
                                        return Ok(1); // No questions, nothing to parse
                                    }
                                    // Question section starts immediately after the DNS header
                                    let mut question_start =
                                        dns_start + core::mem::size_of::<DnsHdr>();
                                    let data: *const u8 = question_start as *const u8;
                                    // let x = unsafe{bpf_skb_load_bytes_relative(ctx, offset, to, len, start_header)}
                                    if question_start + 8 > data_end {
                                        return Ok(0);
                                    }
                                    let len = unsafe {
                                        // bpf_skb_load_bytes(skb, question_start, , len)
                                        let mut buf = [0u8; 128];

                                        bpf_probe_read_kernel_buf(data, &mut buf);
                                        let my_str = core::str::from_utf8_unchecked(&buf);
                                        info!(
                                            &ctx,
                                            "got a dns packet with qdcount{} first label {}ii",
                                            qdcount,
                                            my_str
                                        );
                                        let hash = djb2_hash_dns(&buf);
                                        let final_hash = hash ^ pod_bpf_map.namespace_hash;
                                        let final_hash = final_hash as u64;
                                        info!(&ctx, "domain:{},hash:{}", my_str, hash);

                                        if let Some(value) =
                                            KRONOS_ALLOW_NETWORK_MAP.get(&label_namespace_key)
                                        {
                                            if let NetworkAllowValue::LNValue { dns, udp, tcp } =
                                                value
                                            {
                                                let count = dns.count;
                                                let action = dns.action;

                                                // Handle "only allow" logic
                                                if count > 0 {
                                                    return handle_net_allow(
                                                        final_hash, action, direction,
                                                    );
                                                }
                                            }
                                        }

                                        // Check fallback DNS map when not in "only allow"
                                        let ret = handle_net(final_hash, direction);
                                        match ret {
                                            Ok(x) => {
                                                if x == 0 {
                                                    info!(&ctx, "dns packet is blocked");
                                                }
                                            }
                                            _ => {}
                                        }

                                        return ret;
                                    };
                                }
                                _ => {
                                    let hash = des as u64 ^ label_namespace_key;

                                    if let Some(value) =
                                        KRONOS_ALLOW_NETWORK_MAP.get(&label_namespace_key)
                                    {
                                        if let NetworkAllowValue::LNValue { dns, udp, tcp } = value
                                        {
                                            let count = udp.count;
                                            let action = udp.action;

                                            // Handle "only allow" logic
                                            if count > 0 {
                                                return handle_net_allow(hash, action, direction);
                                            }
                                        }
                                    }

                                    // Check fallback UDP map when not in "only allow"
                                    return handle_net(hash, direction);
                                }
                            }
                        }
                        _ => {
                            // Add logic for other protocols other than TCP and UDP
                        }
                    }

                    return Ok(1);
                    // }
                }
                _ => {}
            }
        }
    }
    // ctx.load()

    Ok(1)
}

#[inline]
fn handle_net_allow(hash: u64, action: u8, direction: i8) -> Result<i32, i32> {
    if let Some(value) = unsafe { KRONOS_ALLOW_NETWORK_MAP.get(&hash) } {
        if let NetworkAllowValue::Rule(rule) = value {
            if direction != rule.direction || rule.direction != 0 {
                // This logic checks the direction is same or applied for both else it
                // will check the net_map for any rules
                return handle_net(hash, direction);
            }

            let req_count = rule.num_of_request + 1;

            if let Some(max_request) = rule.max_req {
                if req_count > max_request {
                    // Exceeds allowed request count, drop the packet
                    // create an alert
                    return Ok(0);
                }
            }

            // Allow the packet
            return Ok(1);
        }
    } else if action == 0 {
        // Audit action, allow with alert
        return Ok(1);
    } else if action == 2 {
        return Ok(1);
    }
    // Block action, drop the packet
    Ok(0)
}

#[inline]
fn handle_net(hash: u64, direction: i8) -> Result<i32, i32> {
    if let Some(rule) = unsafe { KRONOS_NETWORK_MAP.get(&hash) } {
        if direction != rule.direction || rule.direction != 0 {
            // This logic checks the direction is same or applied for both else it
            // will check the net_map for any rules.
            // Rule doesn't exists for this direction so we allow the packet
            return Ok(1);
        }
        let action = rule.action;

        if action == 0 {
            if let Some(max_request) = rule.max_req {
                let req_count = rule.num_of_request + 1;
                if req_count > max_request {
                    // Exceeds allowed request count, drop the packet
                    return Ok(0);
                }
            }
            // Allow the packet within request limit
            return Ok(1);
        }

        // Deny action, drop the packet
        return Ok(0);
    }
    Ok(1)
}

#[lsm(hook = "file_open")]
pub fn lsm_file_open(ctx: LsmContext) -> i32 {
    match unsafe { try_file_open(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_file_open(ctx: LsmContext) -> Result<i32, i32> {
    // info!(&ctx, "file open called ");
    let cgroupid = unsafe { bpf_get_current_ancestor_cgroup_id(3) };

    // info!(&ctx, "cgroupid {}", cgroupid);
    // pass the function if the id cant be retrieved as the return value 0 indicates thaat cgroupid can't be retrieved
    if cgroupid == 0 {
        return Ok(0);
    }

    if let Some(pod_bpf_map) = KRONOS_PODS.get(&cgroupid) {
        // info!(&ctx, "cgroupid : {}", cgroupid);
        let target = pod_bpf_map.target;
        // info!(&ctx, "is file target: {}", target & 1);
        if (target & 1) != 0 {
            let file: *const vmlinux::file = unsafe { ctx.arg(0) };

            // Buffer to store the full path
            let mut path_buf: [u8; 256] = [0; 256];
            let mut path_ptr = unsafe { &(*file).f_path as *const vmlinux::path };

            let d_name = unsafe { (*(*path_ptr).dentry).d_name };
            let res = helpers::bpf_probe_read_kernel_str_bytes(d_name.name, &mut path_buf);

            // let hh = helpers::bpf_d_path(, buf, sz)
            match res.ok() {
                Some(bytes) => {
                    // info!(&ctx, "read file name from kernel");
                    let my_str = core::str::from_utf8_unchecked(bytes);
                    // info!(&ctx, "file name: {}", my_str);
                    let hash = djb2_hash(bytes);
                    let hash = (hash as u64) ^ (pod_bpf_map.namespace_hash as u64);

                    // info!(&ctx, "hash for file {}", hash);
                    if let Some(file) = KRONOS_FILE_MAP.get(&hash) {
                        info!(&ctx, "got file");
                        if file.is_file == 2 {
                            // this implies source exists
                            let res = ctx.command();
                            match res.ok() {
                                Some(comm) => {
                                    let command = core::str::from_utf8_unchecked(&comm);
                                    //
                                    let command_slice = &comm[..16.min(comm.len())]; // This limits to 16 bytes or the length of comm, whichever is smaller
                                    let source_hash = djb2_hash(command_slice);

                                    let new_hash = hash ^ (source_hash as u64);

                                    info!(&ctx, "command name:{} , hash :{}", command, source_hash);

                                    if let Some(_) = KRONOS_SOURCE_MAP.get(&new_hash) {
                                        info!(&ctx, "got key from source map");
                                        // Check source for specific source file if exists
                                        if file.file_action == 1 && (file.only_allow != 1) {
                                            let ret = -1;
                                            return Ok(ret);
                                        }
                                    } else if file.only_allow == 1 {
                                        // block other binaries accessing this file when onlyallow
                                        // is true.
                                        return Ok(-1);
                                    }
                                }
                                None => {}
                            }
                        } else if file.only_allow == 1 {
                            // execute the action if only file rule is present
                            return Ok(-1);
                        } else if file.is_file == 1 {
                            if file.file_action == 1 {
                                return Ok(-1);
                            }
                        }
                    }

                    // info!(&ctx, "hash:{} , file:{}", hash, my_str);
                }
                None => {}
            }
        }
    }

    // helpers::bpf_probe_read_kernel_str_bytes(hh, dest)

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
