//! Public CASE entrypoints against an in-memory responder; no device I/O.
use super::*;
use crate::connection_budget::{ConnectBusy, ConnectDeadline, ConnectStage};
use crate::messages::{ProtocolMessageHeader, SecureChannelGeneralCode, SecureChannelProtocolCode};
use crate::{im, tlv, util};
use std::collections::VecDeque;
use tokio::time::Instant;

struct Certificates(p256::SecretKey);
impl certmanager::CertManager for Certificates {
    fn get_ca_cert(&self) -> Result<Vec<u8>> {
        anyhow::bail!("unused fixture certificate")
    }
    fn get_ca_key(&self) -> Result<p256::SecretKey> {
        Ok(self.0.clone())
    }
    fn get_ca_public_key(&self) -> Result<Vec<u8>> {
        Ok(self.0.public_key().to_sec1_bytes().to_vec())
    }
    fn get_user_cert(&self, _: u64) -> Result<Vec<u8>> {
        anyhow::bail!("unused fixture certificate")
    }
    fn get_user_key(&self, _: u64) -> Result<p256::SecretKey> {
        Ok(self.0.clone())
    }
    fn get_fabric_id(&self) -> u64 {
        1
    }
    fn get_ipk_epoch_key(&self) -> Vec<u8> {
        vec![0; 16]
    }
}

enum Reply {
    Busy(u32),
    Resume,
    Hang,
    Fail,
}
struct Responder {
    replies: tokio::sync::Mutex<VecDeque<(Duration, Reply)>>,
    current: tokio::sync::Mutex<Option<(Duration, Vec<u8>)>>,
    requests: std::sync::Mutex<Vec<(Instant, bool)>>,
}
impl Responder {
    fn new(replies: Vec<(Duration, Reply)>) -> Arc<Self> {
        Arc::new(Self {
            replies: tokio::sync::Mutex::new(replies.into()),
            current: tokio::sync::Mutex::new(None),
            requests: Default::default(),
        })
    }
}

#[async_trait::async_trait]
impl ConnectionTrait for Responder {
    async fn send(&self, data: &[u8]) -> Result<()> {
        let message = Message::decode(data)?;
        assert_eq!(
            message.protocol_header.protocol_id, 0,
            "no physical IM command"
        );
        if message.protocol_header.opcode != ProtocolMessageHeader::OPCODE_CASE_SIGMA1 {
            return Ok(());
        }
        self.requests
            .lock()
            .unwrap()
            .push((Instant::now(), message.tlv.get_octet_string(&[6]).is_some()));
        let (delay, reply) = self
            .replies
            .lock()
            .await
            .pop_front()
            .unwrap_or((Duration::ZERO, Reply::Hang));
        let header = &message.protocol_header;
        let bytes = match reply {
            Reply::Busy(ms) => {
                let mut body = crate::device_messages::status_report(
                    header.exchange_id,
                    SecureChannelGeneralCode::Busy as u16,
                    0,
                    SecureChannelProtocolCode::Busy as u16,
                    message.message_header.message_counter as i64,
                )?;
                body.extend_from_slice(&ms.to_le_bytes());
                session::Session::new().encode_message(&body)?
            }
            Reply::Resume => {
                let nonce = message.tlv.get_octet_string(&[1]).unwrap();
                let new_id = [3; 16];
                let mut salt = nonce.to_vec();
                salt.extend_from_slice(&new_id);
                let key = util::cryptoutil::hkdf_sha256(&salt, &[2; 32], b"Sigma2_Resume", 16)?;
                let mic = util::cryptoutil::aes128_ccm_encrypt(
                    key.as_slice().into(),
                    b"NCASE_SigmaS2",
                    &[],
                    &[],
                )?;
                let mut tlv = tlv::TlvBuffer::new();
                tlv.write_anon_struct()?;
                tlv.write_octetstring(1, &new_id)?;
                tlv.write_octetstring(2, &mic)?;
                tlv.write_uint16(3, 42)?;
                tlv.write_struct_end()?;
                session::Session::new().encode_message(&crate::device_messages::sigma2_msg(
                    header.exchange_id,
                    &tlv.data,
                    message.message_header.message_counter as i64,
                )?)?
            }
            Reply::Hang => return Ok(()),
            Reply::Fail => {
                *self.current.lock().await = Some((delay, Vec::new()));
                return Ok(());
            }
        };
        *self.current.lock().await = Some((delay, bytes));
        Ok(())
    }
    async fn receive(&self, _: Duration) -> Result<Vec<u8>> {
        let next = self.current.lock().await.take();
        if let Some((delay, bytes)) = next {
            tokio::time::sleep(delay).await;
            if bytes.is_empty() {
                anyhow::bail!("opaque-secret-fixture-must-not-be-logged")
            }
            Ok(bytes)
        } else {
            std::future::pending().await
        }
    }
    fn is_reliable(&self) -> bool {
        true
    }
}

async fn controller(resume: bool) -> Arc<Controller> {
    let cm: Arc<dyn certmanager::CertManager> = Arc::new(Certificates(p256::SecretKey::random(
        &mut rand::thread_rng(),
    )));
    let transport = transport::Transport::new("127.0.0.1:0").await.unwrap();
    let controller = Controller::new(&cm, &transport, 1).unwrap();
    if resume {
        controller.resumption.lock().await.insert(
            7,
            sigma::ResumptionRecord {
                resumption_id: [1; 16],
                shared_secret: [2; 32],
            },
        );
    }
    controller
}

#[tokio::test(start_paused = true)]
async fn resume_busy_waits_before_retry_and_then_authenticates() {
    let controller = controller(true).await;
    let responder = Responder::new(vec![
        (Duration::ZERO, Reply::Busy(5000)),
        (Duration::ZERO, Reply::Resume),
    ]);
    let conn: Arc<dyn ConnectionTrait> = responder.clone();
    let started = Instant::now();
    let result = controller
        .auth_sigma_with_busy_retry_until(&conn, 7, 1, started + Duration::from_secs(10))
        .await
        .unwrap();
    assert_eq!(result.session_id, 42);
    let sent = responder.requests.lock().unwrap();
    assert_eq!(sent.len(), 2);
    assert!(sent.iter().all(|(_, resume)| *resume));
    assert!(sent[1].0.duration_since(sent[0].0) >= Duration::from_secs(5));
}

#[tokio::test(start_paused = true)]
async fn full_case_busy_uses_the_same_wait_and_deferral_policy() {
    let controller = controller(false).await;
    let responder = Responder::new(vec![
        (Duration::ZERO, Reply::Busy(5000)),
        (Duration::ZERO, Reply::Busy(5000)),
    ]);
    let conn: Arc<dyn ConnectionTrait> = responder.clone();
    let started = Instant::now();
    let error = controller
        .auth_sigma_with_busy_retry_until(&conn, 7, 1, started + Duration::from_secs(8))
        .await
        .err()
        .unwrap();
    let busy = error.downcast_ref::<ConnectBusy>().unwrap();
    assert!(busy.retry_at >= started + Duration::from_secs(10));
    let sent = responder.requests.lock().unwrap();
    assert_eq!(sent.len(), 2);
    assert!(sent.iter().all(|(_, resume)| !*resume));
    assert!(sent[1].0.duration_since(sent[0].0) >= Duration::from_secs(5));
}

#[tokio::test(start_paused = true)]
async fn legacy_public_api_also_honors_resume_busy_without_new_deadline() {
    let controller = controller(true).await;
    let responder = Responder::new(vec![
        (Duration::ZERO, Reply::Busy(5000)),
        (Duration::ZERO, Reply::Resume),
    ]);
    let conn: Arc<dyn ConnectionTrait> = responder.clone();
    assert_eq!(
        controller
            .auth_sigma_with_busy_retry(&conn, 7, 1)
            .await
            .unwrap()
            .session_id,
        42
    );
    let sent = responder.requests.lock().unwrap();
    assert_eq!(sent.len(), 2);
    assert!(sent.iter().all(|(_, resume)| *resume));
    assert!(sent[1].0.duration_since(sent[0].0) >= Duration::from_secs(5));
}

#[tokio::test(start_paused = true)]
async fn busy_longer_than_remaining_deadline_does_not_start_full_case() {
    let controller = controller(true).await;
    let responder = Responder::new(vec![(Duration::ZERO, Reply::Busy(5000))]);
    let conn: Arc<dyn ConnectionTrait> = responder.clone();
    let started = Instant::now();
    let error = controller
        .auth_sigma_with_busy_retry_until(&conn, 7, 1, started + Duration::from_secs(2))
        .await
        .err()
        .unwrap();
    assert!(error.is::<ConnectBusy>());
    assert_eq!(responder.requests.lock().unwrap().len(), 1);
    assert!(Instant::now().duration_since(started) < Duration::from_secs(2));
}

#[tokio::test(start_paused = true)]
async fn expired_deadline_never_sends_and_hung_resume_returns_typed_stage() {
    let controller = controller(true).await;
    let responder = Responder::new(vec![]);
    let conn: Arc<dyn ConnectionTrait> = responder.clone();
    let error = controller
        .auth_sigma_with_busy_retry_until(&conn, 7, 1, Instant::now())
        .await
        .err()
        .unwrap();
    assert_eq!(
        error.downcast_ref::<ConnectDeadline>().unwrap().stage,
        ConnectStage::Resume
    );
    assert!(responder.requests.lock().unwrap().is_empty());
    let end = Instant::now() + Duration::from_secs(2);
    let error = controller
        .auth_sigma_with_busy_retry_until(&conn, 7, 1, end)
        .await
        .err()
        .unwrap();
    assert_eq!(
        error.downcast_ref::<ConnectDeadline>().unwrap().stage,
        ConnectStage::Resume
    );
    assert_eq!(Instant::now(), end);
}

#[tokio::test(start_paused = true)]
async fn bounded_api_never_shortens_an_advertised_minimum_wait() {
    let controller = controller(true).await;
    let responder = Responder::new(vec![(Duration::ZERO, Reply::Busy(120_000))]);
    let conn: Arc<dyn ConnectionTrait> = responder;
    let started = Instant::now();
    let error = controller
        .auth_sigma_with_busy_retry_until(&conn, 7, 1, started + Duration::from_secs(10))
        .await
        .err()
        .unwrap();
    assert_eq!(
        error.downcast_ref::<ConnectBusy>().unwrap().retry_at,
        started + Duration::from_secs(120)
    );
}

#[tokio::test(start_paused = true)]
async fn late_valid_resume_cannot_return_connection_authority() {
    let controller = controller(true).await;
    let responder = Responder::new(vec![(Duration::from_secs(2), Reply::Resume)]);
    let conn: Arc<dyn ConnectionTrait> = responder;
    let error = controller
        .auth_sigma_with_busy_retry_until(&conn, 7, 1, Instant::now() + Duration::from_secs(2))
        .await
        .err()
        .unwrap();
    assert!(error.is::<ConnectDeadline>());
}

#[tokio::test(start_paused = true)]
async fn cancelling_busy_wait_never_retries_after_caller_is_gone() {
    let controller = controller(true).await;
    let responder = Responder::new(vec![(Duration::ZERO, Reply::Busy(5000))]);
    let conn: Arc<dyn ConnectionTrait> = responder.clone();
    let task = tokio::spawn(async move {
        controller
            .auth_sigma_with_busy_retry_until(&conn, 7, 1, Instant::now() + Duration::from_secs(20))
            .await
    });
    while responder.requests.lock().unwrap().is_empty() {
        tokio::task::yield_now().await;
    }
    tokio::task::yield_now().await;
    task.abort();
    let _ = task.await;
    tokio::time::advance(Duration::from_secs(30)).await;
    assert_eq!(responder.requests.lock().unwrap().len(), 1);
}

#[tokio::test(start_paused = true)]
async fn failed_case_does_not_close_an_unrelated_subscription() {
    let controller = controller(true).await;
    let responder = Responder::new(vec![(Duration::ZERO, Reply::Fail)]);
    let conn: Arc<dyn ConnectionTrait> = responder;
    let other: Arc<dyn ConnectionTrait> = Responder::new(vec![]);
    let live = Connection::from_parts(other, session::Session::new());
    let rx = live.active.register_subscription(99);
    let mut subscription = Subscription {
        subscription_id: 99,
        max_interval: 30,
        priming_attribute_reports: vec![],
        priming_event_reports: vec![],
        rx,
        registry: live.active.subscriptions_handle(),
    };
    assert!(controller
        .auth_sigma_with_busy_retry_until(&conn, 7, 1, Instant::now() + Duration::from_secs(2))
        .await
        .is_err());
    live.active
        .subscriptions_handle()
        .lock()
        .unwrap()
        .get(&99)
        .unwrap()
        .try_send(im::ReportUpdate {
            subscription_id: 99,
            attribute_reports: vec![],
            event_reports: vec![],
        })
        .unwrap();
    assert_eq!(subscription.next().await.unwrap().subscription_id, 99);
}
