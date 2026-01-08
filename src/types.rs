//! Data types used by the protocol.

use std::{
    net::{IpAddr, SocketAddr},
    ops::RangeInclusive,
    time::Duration,
};

use ipnet::IpNet;
use num_enum::{IntoPrimitive, TryFromPrimitive};
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};
pub use structured::ColumnStatistics;

/// The data source key, either a numeric ID or a name.
#[derive(Debug, Deserialize, Serialize)]
pub enum DataSourceKey<'a> {
    Id(u32),
    Name(&'a str),
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DataSource {
    pub id: u32,
    pub name: String,

    pub server_name: String,
    pub address: SocketAddr,

    pub data_type: DataType,
    pub source: String,
    pub kind: Option<String>,

    pub description: String,
}

/// The type of data that a data source provides.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, IntoPrimitive, TryFromPrimitive)]
#[serde(into = "u16", try_from = "u16")]
#[repr(u16)]
pub enum DataType {
    /// comma-separated values
    Csv = 0,
    /// line-based text data
    Log = 1,
    /// time series data
    TimeSeries = 2,
}

/// CPU, memory, and disk usage.
#[derive(Debug, Deserialize, Serialize)]
pub struct ResourceUsage {
    /// The average CPU usage in percent.
    pub cpu_usage: f32,

    /// The RAM size in bytes.
    pub total_memory: u64,

    /// The amount of used RAM in bytes.
    pub used_memory: u64,

    /// The disk space in bytes that is currently used.
    pub disk_used_bytes: u64,

    /// The disk space in bytes that is available to non-root users.
    pub disk_available_bytes: u64,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Process {
    pub user: String,
    pub cpu_usage: f32,
    pub mem_usage: f64,
    pub start_time: i64,
    pub command: String,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct HostNetworkGroup {
    pub hosts: Vec<IpAddr>,
    pub networks: Vec<IpNet>,
    pub ip_ranges: Vec<RangeInclusive<IpAddr>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[repr(u32)]
pub enum SamplingKind {
    Conn = 0,
    Dns = 1,
    Http = 2,
    Rdp = 3,
}

// A policy for time series sampling.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SamplingPolicy {
    pub id: u32,
    pub kind: SamplingKind,
    pub interval: Duration,
    pub period: Duration,
    pub offset: i32,
    pub src_ip: Option<IpAddr>,
    pub dst_ip: Option<IpAddr>,
    pub node: Option<String>,
    pub column: Option<u32>,
}

// IP address, port numbers, and protocols.
pub type TrafficFilterRule = (IpNet, Option<Vec<u16>>, Option<Vec<u16>>);

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[repr(u8)]
pub enum EventCategory {
    Reconnaissance = 1,
    InitialAccess = 2,
    Execution = 3,
    CredentialAccess = 4,
    Discovery = 5,
    LateralMovement = 6,
    CommandAndControl = 7,
    Exfiltration = 8,
    Impact = 9,
    Collection = 10,
    DefenseEvasion = 11,
    Persistence = 12,
    PrivilegeEscalation = 13,
    ResourceDevelopment = 14,
}

#[derive(Clone, Copy, Debug, Deserialize_repr, Eq, PartialEq, Serialize_repr)]
#[repr(u8)]
pub enum LabelDbKind {
    Ip = 0,
    Url = 1,
    Token = 2,
    Regex = 3,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub enum RuleKind {
    Os,
    AgentSoftware,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UserAgent {
    pub name: String,
    pub header: String,
    pub kind: RuleKind,
    pub last_modification_time: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LabelDbRule {
    pub rule_id: u32,
    pub category: Option<EventCategory>,
    pub name: String,
    pub kind: Option<RuleKind>,
    pub description: Option<String>,
    pub references: Option<Vec<String>>,
    pub samples: Option<Vec<String>>,
    pub signatures: Option<Vec<String>>,
    pub confidence: Option<f32>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LabelDb {
    pub id: u32,
    pub name: String,
    pub description: Option<String>,
    pub kind: LabelDbKind,
    pub category: Option<EventCategory>,
    pub version: String,
    pub patterns: Vec<LabelDbRule>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub enum Status {
    Ready,
    Idle,
}

/// Threat level of a detection event.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ThreatLevel {
    VeryLow,
    Low,
    Medium,
    High,
    VeryHigh,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ColumnStatisticsUpdate {
    pub cluster_id: u32,
    pub column_statistics: Vec<ColumnStatistics>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TimeCount {
    pub time: jiff::civil::DateTime,
    pub count: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TimeSeries {
    pub count_index: Option<usize>,
    pub series: Vec<TimeCount>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TimeSeriesUpdate {
    pub cluster_id: String,
    pub time_series: Vec<TimeSeries>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UpdateClusterRequest {
    pub cluster_id: i32,
    pub detector_id: i32,
    pub signature: String,
    pub score: Option<f64>,
    pub size: i64,
    pub event_ids: Vec<(i64, String)>,
    pub status_id: i32,
    pub labels: Option<Vec<String>>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OutlierInfo {
    pub id: i64,
    pub rank: i64,
    pub distance: f64,
    pub sensor: String,
}

#[derive(Serialize, Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[allow(clippy::module_name_repetitions)]
pub enum EventKind {
    DnsCovertChannel,
    HttpThreat,
    RdpBruteForce,
    RepeatedHttpSessions,
    ExtraThreat,
    TorConnection,
    DomainGenerationAlgorithm,
    FtpBruteForce,
    FtpPlainText,
    PortScan,
    MultiHostPortScan,
    NonBrowser,
    LdapBruteForce,
    LdapPlainText,
    ExternalDdos,
    CryptocurrencyMiningPool,
    BlocklistConn,
    BlocklistDns,
    BlocklistDceRpc,
    BlocklistFtp,
    BlocklistHttp,
    BlocklistKerberos,
    BlocklistLdap,
    BlocklistMqtt,
    BlocklistNfs,
    BlocklistNtlm,
    BlocklistRdp,
    BlocklistSmb,
    BlocklistSmtp,
    BlocklistSsh,
    BlocklistTls,
    WindowsThreat,
    NetworkThreat,
    LockyRansomware,
    SuspiciousTlsTraffic,
    BlocklistBootp,
    BlocklistDhcp,
    TorConnectionConn,
    BlocklistRadius,
    BlocklistMalformedDns,
    UnusualDestinationPattern,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EventMessage {
    #[serde(with = "jiff::fmt::serde::timestamp::nanosecond::required")]
    pub time: jiff::Timestamp,
    pub kind: EventKind,
    #[serde(with = "serde_bytes")]
    pub fields: Vec<u8>,
}

#[cfg(test)]
mod tests {
    #[cfg(any(feature = "client", feature = "server"))]
    use super::*;

    #[cfg(any(feature = "client", feature = "server"))]
    #[test]
    fn event_kind_serialization_round_trip() {
        // Test that all EventKind variants can be serialized and deserialized
        let test_cases = vec![
            EventKind::DnsCovertChannel,
            EventKind::HttpThreat,
            EventKind::RdpBruteForce,
            EventKind::RepeatedHttpSessions,
            EventKind::ExtraThreat,
            EventKind::TorConnection,
            EventKind::DomainGenerationAlgorithm,
            EventKind::FtpBruteForce,
            EventKind::FtpPlainText,
            EventKind::PortScan,
            EventKind::MultiHostPortScan,
            EventKind::NonBrowser,
            EventKind::LdapBruteForce,
            EventKind::LdapPlainText,
            EventKind::ExternalDdos,
            EventKind::CryptocurrencyMiningPool,
            EventKind::BlocklistConn,
            EventKind::BlocklistDns,
            EventKind::BlocklistDceRpc,
            EventKind::BlocklistFtp,
            EventKind::BlocklistHttp,
            EventKind::BlocklistKerberos,
            EventKind::BlocklistLdap,
            EventKind::BlocklistMqtt,
            EventKind::BlocklistNfs,
            EventKind::BlocklistNtlm,
            EventKind::BlocklistRdp,
            EventKind::BlocklistSmb,
            EventKind::BlocklistSmtp,
            EventKind::BlocklistSsh,
            EventKind::BlocklistTls,
            EventKind::WindowsThreat,
            EventKind::NetworkThreat,
            EventKind::LockyRansomware,
            EventKind::SuspiciousTlsTraffic,
            EventKind::BlocklistBootp,
            EventKind::BlocklistDhcp,
            EventKind::TorConnectionConn,
            EventKind::BlocklistRadius,
            EventKind::BlocklistMalformedDns,
            EventKind::UnusualDestinationPattern,
        ];

        for kind in test_cases {
            // Serialize with bincode (used in the protocol)
            let serialized = bincode::serde::encode_to_vec(
                kind,
                bincode::config::standard().with_fixed_int_encoding(),
            )
            .expect("serialization should succeed");

            // Deserialize back
            let (deserialized, _len): (EventKind, usize) = bincode::serde::decode_from_slice(
                &serialized,
                bincode::config::standard().with_fixed_int_encoding(),
            )
            .expect("deserialization should succeed");

            // Verify round-trip
            assert_eq!(kind, deserialized, "EventKind {kind:?} failed round-trip");
        }
    }

    #[cfg(any(feature = "client", feature = "server"))]
    #[test]
    fn event_message_with_blocklist_radius_serialization() {
        // Test EventMessage with BlocklistRadius variant
        let event = EventMessage {
            time: jiff::Timestamp::now(),
            kind: EventKind::BlocklistRadius,
            fields: vec![1, 2, 3, 4, 5],
        };

        // Serialize with bincode (used in the protocol)
        let serialized = bincode::serde::encode_to_vec(
            &event,
            bincode::config::standard().with_fixed_int_encoding(),
        )
        .expect("serialization should succeed");

        // Deserialize back
        let (deserialized, _len): (EventMessage, usize) = bincode::serde::decode_from_slice(
            &serialized,
            bincode::config::standard().with_fixed_int_encoding(),
        )
        .expect("deserialization should succeed");

        // Verify the kind matches
        assert_eq!(
            event.kind, deserialized.kind,
            "EventKind should match after round-trip"
        );
        assert_eq!(
            event.fields, deserialized.fields,
            "Fields should match after round-trip"
        );
    }

    #[cfg(any(feature = "client", feature = "server"))]
    #[test]
    fn threat_level_serialization_round_trip() {
        // Test that all ThreatLevel variants can be serialized and deserialized
        let test_cases = vec![
            ThreatLevel::VeryLow,
            ThreatLevel::Low,
            ThreatLevel::Medium,
            ThreatLevel::High,
            ThreatLevel::VeryHigh,
        ];

        for level in test_cases {
            // Serialize with bincode (used in the protocol)
            let serialized = bincode::serde::encode_to_vec(
                level,
                bincode::config::standard().with_fixed_int_encoding(),
            )
            .expect("serialization should succeed");

            // Deserialize back
            let (deserialized, _len): (ThreatLevel, usize) = bincode::serde::decode_from_slice(
                &serialized,
                bincode::config::standard().with_fixed_int_encoding(),
            )
            .expect("deserialization should succeed");

            // Verify round-trip
            assert_eq!(
                level, deserialized,
                "ThreatLevel {level:?} failed round-trip"
            );
        }
    }
}
