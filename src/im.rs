//! Typed Interaction Model report layer.
//!
//! Parses ReportData and SubscribeResponse messages into typed structures,
//! replacing manual TLV path navigation. Used by [crate::controller::Connection]
//! for chunked report reassembly (reads and subscriptions) and by the
//! subscription event stream ([crate::controller::Subscription]).

use anyhow::Result;

use crate::tlv::{TlvItem, TlvItemValue};

/// Attribute path from an AttributePathIB. Fields absent in the report
/// (e.g. wildcard responses with unusual encodings) are None.
#[derive(Debug, Clone, PartialEq)]
pub struct AttributePath {
    pub endpoint: Option<u16>,
    pub cluster: Option<u32>,
    pub attribute: Option<u32>,
}

/// Payload of a single attribute report - either a value or a status code.
#[derive(Debug, Clone, PartialEq)]
pub enum AttributeData {
    Value(TlvItemValue),
    Status { status: u8, cluster_status: Option<u8> },
}

/// One decoded AttributeReportIB.
#[derive(Debug, Clone, PartialEq)]
pub struct AttributeReport {
    pub path: AttributePath,
    pub data: AttributeData,
    pub data_version: Option<u32>,
}

/// One decoded EventReportIB.
#[derive(Debug, Clone, PartialEq)]
pub struct EventReport {
    pub endpoint: Option<u16>,
    pub cluster: Option<u32>,
    pub event: Option<u32>,
    pub event_number: Option<u64>,
    pub data: Option<TlvItemValue>,
}

/// Decoded ReportData message (single chunk or merged multi-chunk).
#[derive(Debug, Clone, Default)]
pub struct ReportData {
    pub subscription_id: Option<u32>,
    pub attribute_reports: Vec<AttributeReport>,
    pub event_reports: Vec<EventReport>,
    pub more_chunks: bool,
    pub suppress_response: bool,
}

impl ReportData {
    /// Parse the TLV payload of an IM ReportData message.
    /// Missing AttributeReports/EventReports lists are not an error
    /// (status-only or event-only reports).
    pub fn parse(tlv: &TlvItem) -> Result<ReportData> {
        let mut out = ReportData {
            subscription_id: tlv.get_u32(&[0]),
            more_chunks: tlv.get_bool(&[3]).unwrap_or(false),
            suppress_response: tlv.get_bool(&[4]).unwrap_or(false),
            ..Default::default()
        };

        if let Some(reports) = tlv.get_item(&[1]) {
            if let TlvItemValue::List(list) = &reports.value {
                for ib in list {
                    if let Some(report) = parse_attribute_report_ib(ib) {
                        out.attribute_reports.push(report);
                    }
                }
            }
        }

        if let Some(reports) = tlv.get_item(&[2]) {
            if let TlvItemValue::List(list) = &reports.value {
                for ib in list {
                    out.event_reports.push(EventReport {
                        endpoint: ib.get_u16(&[1, 0, 1]),
                        cluster: ib.get_u32(&[1, 0, 2]),
                        event: ib.get_u32(&[1, 0, 3]),
                        event_number: ib.get_u64(&[1, 1]),
                        data: ib.get(&[1, 7]).cloned(),
                    });
                }
            }
        }

        Ok(out)
    }

    /// Append reports from the next chunk; flags are taken from the last chunk.
    pub fn merge(&mut self, next: ReportData) {
        if self.subscription_id.is_none() {
            self.subscription_id = next.subscription_id;
        }
        self.attribute_reports.extend(next.attribute_reports);
        self.event_reports.extend(next.event_reports);
        self.more_chunks = next.more_chunks;
        self.suppress_response = next.suppress_response;
    }
}

fn parse_attribute_report_ib(ib: &TlvItem) -> Option<AttributeReport> {
    if let Some(data) = ib.get(&[1, 2]) {
        Some(AttributeReport {
            path: AttributePath {
                endpoint: ib.get_u16(&[1, 1, 2]),
                cluster: ib.get_u32(&[1, 1, 3]),
                attribute: ib.get_u32(&[1, 1, 4]),
            },
            data: AttributeData::Value(data.clone()),
            data_version: ib.get_u32(&[1, 0]),
        })
    } else {
        ib.get_u8(&[0, 1, 0]).map(|status| AttributeReport {
            path: AttributePath {
                endpoint: ib.get_u16(&[0, 0, 2]),
                cluster: ib.get_u32(&[0, 0, 3]),
                attribute: ib.get_u32(&[0, 0, 4]),
            },
            data: AttributeData::Status {
                status,
                cluster_status: ib.get_u8(&[0, 1, 1]),
            },
            data_version: None,
        })
    }
}

/// Decoded SubscribeResponse message.
#[derive(Debug, Clone)]
pub struct SubscribeResponse {
    pub subscription_id: u32,
    pub max_interval: u16,
}

impl SubscribeResponse {
    /// Parse the TLV payload of an IM SubscribeResponse message.
    pub fn parse(tlv: &TlvItem) -> Result<SubscribeResponse> {
        Ok(SubscribeResponse {
            subscription_id: tlv
                .get_u32(&[0])
                .ok_or_else(|| anyhow::anyhow!("subscribe response missing subscription id"))?,
            max_interval: tlv.get_u16(&[2]).unwrap_or(0),
        })
    }
}

/// One reassembled subscription update delivered by
/// [crate::controller::Subscription::next].
#[derive(Debug, Clone)]
pub struct ReportUpdate {
    pub subscription_id: u32,
    pub attribute_reports: Vec<AttributeReport>,
    pub event_reports: Vec<EventReport>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device_messages::{self, AttrReport};
    use crate::messages::ProtocolMessageHeader;
    use crate::tlv;

    fn parse_payload(msg: &[u8]) -> ReportData {
        let (_, rest) = ProtocolMessageHeader::decode(msg).unwrap();
        let tlv = tlv::decode_tlv(&rest).unwrap();
        ReportData::parse(&tlv).unwrap()
    }

    fn bool_value_tlv(value: bool) -> Vec<u8> {
        let mut buf = tlv::TlvBuffer::new();
        buf.write_bool(2, value).unwrap();
        buf.data
    }

    #[test]
    fn test_parse_data_report() {
        let value_tlv = bool_value_tlv(true);
        let msg = device_messages::im_report_data(
            7,
            &[AttrReport::Data { endpoint: 1, cluster: 6, attribute: 0, value_tlv }],
            -1,
            Some(0x1234),
            false,
        )
        .unwrap();
        let rd = parse_payload(&msg);
        assert_eq!(rd.subscription_id, Some(0x1234));
        assert!(!rd.more_chunks);
        assert_eq!(rd.attribute_reports.len(), 1);
        let rep = &rd.attribute_reports[0];
        assert_eq!(rep.path.endpoint, Some(1));
        assert_eq!(rep.path.cluster, Some(6));
        assert_eq!(rep.path.attribute, Some(0));
        assert_eq!(rep.data, AttributeData::Value(TlvItemValue::Bool(true)));
        assert_eq!(rep.data_version, Some(0));
    }

    #[test]
    fn test_parse_status_report() {
        let msg = device_messages::im_report_data_status(7, 1, 6, 0, 0x86, -1).unwrap();
        let rd = parse_payload(&msg);
        assert_eq!(rd.attribute_reports.len(), 1);
        let rep = &rd.attribute_reports[0];
        assert_eq!(rep.path.endpoint, Some(1));
        assert_eq!(
            rep.data,
            AttributeData::Status { status: 0x86, cluster_status: None }
        );
    }

    #[test]
    fn test_parse_mixed_reports_and_chunk_flag() {
        let value_tlv = bool_value_tlv(false);
        let msg = device_messages::im_report_data(
            7,
            &[
                AttrReport::Data { endpoint: 1, cluster: 6, attribute: 0, value_tlv },
                AttrReport::Status { endpoint: 2, cluster: 8, attribute: 3, status: 1 },
            ],
            -1,
            None,
            true,
        )
        .unwrap();
        let rd = parse_payload(&msg);
        assert_eq!(rd.subscription_id, None);
        assert!(rd.more_chunks);
        assert_eq!(rd.attribute_reports.len(), 2);
        assert!(matches!(rd.attribute_reports[0].data, AttributeData::Value(_)));
        assert!(matches!(rd.attribute_reports[1].data, AttributeData::Status { status: 1, .. }));
    }

    #[test]
    fn test_parse_suppress_response() {
        let mut buf = tlv::TlvBuffer::new();
        buf.write_anon_struct().unwrap();
        buf.write_array(1).unwrap();
        buf.write_struct_end().unwrap();
        buf.write_bool(4, true).unwrap();
        buf.write_struct_end().unwrap();
        let tlv = tlv::decode_tlv(&buf.data).unwrap();
        let rd = ReportData::parse(&tlv).unwrap();
        assert!(rd.suppress_response);
        assert!(rd.attribute_reports.is_empty());
    }

    #[test]
    fn test_parse_event_report() {
        let mut buf = tlv::TlvBuffer::new();
        buf.write_anon_struct().unwrap();
        buf.write_uint32(0, 99).unwrap();
        buf.write_array(2).unwrap();
        buf.write_anon_struct().unwrap();
        buf.write_struct(1).unwrap();
        buf.write_list(0).unwrap();
        buf.write_uint16(1, 1).unwrap();
        buf.write_uint32(2, 0x101).unwrap();
        buf.write_uint32(3, 2).unwrap();
        buf.write_struct_end().unwrap();
        buf.write_uint64(1, 42).unwrap();
        buf.write_uint8(7, 5).unwrap();
        buf.write_struct_end().unwrap();
        buf.write_struct_end().unwrap();
        buf.write_struct_end().unwrap();
        let tlv = tlv::decode_tlv(&buf.data).unwrap();
        let rd = ReportData::parse(&tlv).unwrap();
        assert_eq!(rd.subscription_id, Some(99));
        assert_eq!(rd.event_reports.len(), 1);
        let ev = &rd.event_reports[0];
        assert_eq!(ev.endpoint, Some(1));
        assert_eq!(ev.cluster, Some(0x101));
        assert_eq!(ev.event, Some(2));
        assert_eq!(ev.event_number, Some(42));
        assert_eq!(ev.data, Some(TlvItemValue::Int(5)));
    }

    #[test]
    fn test_parse_missing_lists() {
        let mut buf = tlv::TlvBuffer::new();
        buf.write_anon_struct().unwrap();
        buf.write_struct_end().unwrap();
        let tlv = tlv::decode_tlv(&buf.data).unwrap();
        let rd = ReportData::parse(&tlv).unwrap();
        assert!(rd.attribute_reports.is_empty());
        assert!(rd.event_reports.is_empty());
        assert!(!rd.more_chunks);
        assert!(!rd.suppress_response);
    }

    #[test]
    fn test_merge() {
        let v1 = bool_value_tlv(true);
        let chunk1 = parse_payload(
            &device_messages::im_report_data(
                7,
                &[AttrReport::Data { endpoint: 1, cluster: 6, attribute: 0, value_tlv: v1 }],
                -1,
                Some(5),
                true,
            )
            .unwrap(),
        );
        let v2 = bool_value_tlv(false);
        let chunk2 = parse_payload(
            &device_messages::im_report_data(
                7,
                &[AttrReport::Data { endpoint: 2, cluster: 6, attribute: 0, value_tlv: v2 }],
                -1,
                None,
                false,
            )
            .unwrap(),
        );
        let mut merged = chunk1;
        assert!(merged.more_chunks);
        merged.merge(chunk2);
        assert!(!merged.more_chunks);
        assert_eq!(merged.subscription_id, Some(5));
        assert_eq!(merged.attribute_reports.len(), 2);
        assert_eq!(merged.attribute_reports[1].path.endpoint, Some(2));
    }

    #[test]
    fn test_parse_subscribe_response() {
        let msg = device_messages::im_subscribe_response(77, 9, -1, 60).unwrap();
        let (_, rest) = ProtocolMessageHeader::decode(&msg).unwrap();
        let tlv = tlv::decode_tlv(&rest).unwrap();
        let sr = SubscribeResponse::parse(&tlv).unwrap();
        assert_eq!(sr.subscription_id, 77);
        assert_eq!(sr.max_interval, 60);
    }
}
