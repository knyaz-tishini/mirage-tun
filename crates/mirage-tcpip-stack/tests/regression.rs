//! Regression tests that reproduce the bugs found in the static analysis.

use std::time::Duration;

use futures::SinkExt;
use tokio::time::timeout;

use mirage_tcpip_stack::phy::ChecksumCapabilities;
use mirage_tcpip_stack::wire::{
    IpAddress, IpProtocol, Ipv4Address, Ipv4Packet, Ipv4Repr,
    UdpPacket, UdpRepr, UDP_HEADER_LEN,
};
use mirage_tcpip_stack::StackBuilder;

fn make_udp_ipv4(
    src_ip: [u8; 4],
    src_port: u16,
    dst_ip: [u8; 4],
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let cksum = ChecksumCapabilities::default();
    let src_addr = Ipv4Address::from(src_ip);
    let dst_addr = Ipv4Address::from(dst_ip);
    let udp_len = UDP_HEADER_LEN + payload.len();
    let ipv4_repr = Ipv4Repr {
        src_addr,
        dst_addr,
        next_header: IpProtocol::Udp,
        payload_len: udp_len,
        hop_limit: 64,
    };
    let udp_repr = UdpRepr { src_port, dst_port };
    let total_len = ipv4_repr.buffer_len() + udp_len;
    let mut buf = vec![0u8; total_len];
    {
        let mut ip_pkt = Ipv4Packet::new_unchecked(&mut buf[..]);
        ipv4_repr.emit(&mut ip_pkt, &cksum);
    }
    let ip_hdr_len = ipv4_repr.buffer_len();
    {
        let mut udp_pkt = UdpPacket::new_unchecked(&mut buf[ip_hdr_len..]);
        udp_repr.emit(
            &mut udp_pkt,
            &IpAddress::from(src_addr),
            &IpAddress::from(dst_addr),
            payload.len(),
            |b| b.copy_from_slice(payload),
            &cksum,
        );
    }
    buf
}

/// before(include) a15e0b72bfc72cb032e67138070da01e325d66f8
/// sink_buf is used in `Stack` to hold a slot for sending any pkt
///
/// the original assumption is that the `poll_ready` -> `start_send` -> `poll_flush`
/// are called sequentially so the slot could be reused and will never get blocked.
///
/// but once the user calls `send_all` on `Stack`, which will not immediate flush the pkt(call `poll_flush`),
/// then `sink_buf` is could be Some(pkt), then it will trigger `Poll::Pending` branch in `Stack::poll_ready`,
/// who did not register the waker correctly, so it will got hanged forever.
#[tokio::test(flavor = "current_thread")]
async fn bug1_poll_ready_waker_registered_via_send_all() {
    let (mut stack, _runner, _udp_socket, _tcp) = StackBuilder::default()
        .enable_udp(true)
        .udp_buffer_size(64)
        .stack_buffer_size(64)
        .build()
        .unwrap();

    let pkt1 = make_udp_ipv4([1, 2, 3, 4], 1111, [5, 6, 7, 8], 9999, b"first");
    let pkt2 = make_udp_ipv4([1, 2, 3, 4], 1111, [5, 6, 7, 8], 9999, b"second");

    let mut stream = futures::stream::iter([Ok(pkt1), Ok(pkt2)]);

    let result = timeout(Duration::from_secs(1), stack.send_all(&mut stream)).await;
    // should be ok after the fix
    assert!(result.is_ok());
}
