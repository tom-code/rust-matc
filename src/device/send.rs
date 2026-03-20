use anyhow::Result;

use crate::{messages, session};

use super::Device;

impl Device {
    pub(crate) async fn send_unencrypted(
        &self,
        addr: &std::net::SocketAddr,
        protocol_data: &[u8],
        node_id: Option<&[u8]>,
    ) -> Result<()> {
        let counter = self.next_counter();
        let mh = messages::MessageHeader {
            flags: 0,
            security_flags: 0,
            session_id: 0,
            message_counter: counter,
            source_node_id: None,
            destination_node_id: node_id.map(|n| n.to_vec()),
        };
        let mut out = mh.encode()?;
        out.extend_from_slice(protocol_data);
        self.socket.send_to(&out, addr).await?;
        Ok(())
    }

    pub(crate) async fn send_encrypted(
        &self,
        addr: &std::net::SocketAddr,
        session: &session::Session,
        protocol_data: &[u8],
    ) -> Result<()> {
        let encoded = session.encode_message(protocol_data)?;
        let _res = self.socket.send_to(&encoded, addr).await?;
        Ok(())
    }

    /*pub(crate) async fn send_pase_encrypted(
        &self,
        addr: &std::net::SocketAddr,
        protocol_data: &[u8],
    ) -> Result<()> {
        let session = self
            .pase_session
            .as_ref()
            .context("No PASE session established")?;
        self.send_encrypted(addr, session, protocol_data).await
    }*/

    pub(crate) async fn send_reply_by_session(
        &self,
        addr: &std::net::SocketAddr,
        session_id: u16,
        data: &[u8],
    ) -> Result<()> {
        if let Some(ses) = self.case_sessions.iter().find(|s| s.my_session_id == session_id) {
            return self.send_encrypted(addr, ses, data).await;
        }
        if let Some(ref ses) = self.pase_session {
            if session_id == ses.my_session_id {
                return self.send_encrypted(addr, ses, data).await;
            }
        }
        self.send_unencrypted(addr, data, None).await
    }

    pub(crate) async fn send_commissioning_reply(
        &self,
        addr: &std::net::SocketAddr,
        session_id: u16,
        data: &[u8],
    ) -> Result<()> {
        self.send_reply_by_session(addr, session_id, data).await
    }
}
