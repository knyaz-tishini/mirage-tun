//! WFP filtering layer identifiers.

use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6,
    FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
    FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4, FWPM_LAYER_ALE_FLOW_ESTABLISHED_V6,
    FWPM_LAYER_INBOUND_IPPACKET_V4, FWPM_LAYER_INBOUND_IPPACKET_V6,
    FWPM_LAYER_INBOUND_TRANSPORT_V4, FWPM_LAYER_INBOUND_TRANSPORT_V6,
    FWPM_LAYER_OUTBOUND_IPPACKET_V4, FWPM_LAYER_OUTBOUND_IPPACKET_V6,
    FWPM_LAYER_OUTBOUND_TRANSPORT_V4, FWPM_LAYER_OUTBOUND_TRANSPORT_V6,
};
use windows_sys::core::GUID;

/// Network layer at which a filter operates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Layer {
    /// Authorize outgoing TCP IPv4 connections.
    ConnectV4,
    /// Authorize outgoing TCP IPv6 connections.
    ConnectV6,
    /// Authorize incoming TCP IPv4 connections.
    AcceptV4,
    /// Authorize incoming TCP IPv6 connections.
    AcceptV6,
    /// Inspect established IPv4 flows.
    FlowEstablishedV4,
    /// Inspect established IPv6 flows.
    FlowEstablishedV6,
    /// Incoming IPv4 packets before IP processing.
    InboundIpPacketV4,
    /// Incoming IPv6 packets before IP processing.
    InboundIpPacketV6,
    /// Outbound IPv4 packets before fragmentation.
    OutboundIpPacketV4,
    /// Outbound IPv6 packets before fragmentation.
    OutboundIpPacketV6,
    /// Incoming IPv4 packets before transport processing.
    InboundTransportV4,
    /// Incoming IPv6 packets before transport processing.
    InboundTransportV6,
    /// Outbound IPv4 packets before network processing.
    OutboundTransportV4,
    /// Outbound IPv6 packets before network processing.
    OutboundTransportV6,
}

impl Layer {
    /// Returns the WFP GUID for this layer.
    pub fn guid(&self) -> &GUID {
        match self {
            Self::ConnectV4 => &FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            Self::ConnectV6 => &FWPM_LAYER_ALE_AUTH_CONNECT_V6,
            Self::AcceptV4 => &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
            Self::AcceptV6 => &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
            Self::FlowEstablishedV4 => &FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4,
            Self::FlowEstablishedV6 => &FWPM_LAYER_ALE_FLOW_ESTABLISHED_V6,
            Self::InboundIpPacketV4 => &FWPM_LAYER_INBOUND_IPPACKET_V4,
            Self::InboundIpPacketV6 => &FWPM_LAYER_INBOUND_IPPACKET_V6,
            Self::OutboundIpPacketV4 => &FWPM_LAYER_OUTBOUND_IPPACKET_V4,
            Self::OutboundIpPacketV6 => &FWPM_LAYER_OUTBOUND_IPPACKET_V6,
            Self::InboundTransportV4 => &FWPM_LAYER_INBOUND_TRANSPORT_V4,
            Self::InboundTransportV6 => &FWPM_LAYER_INBOUND_TRANSPORT_V6,
            Self::OutboundTransportV4 => &FWPM_LAYER_OUTBOUND_TRANSPORT_V4,
            Self::OutboundTransportV6 => &FWPM_LAYER_OUTBOUND_TRANSPORT_V6,
        }
    }
}
