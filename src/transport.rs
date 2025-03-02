use anyhow::{Context, Result};
use std::{collections::HashMap, sync::Arc, time::Duration};
use tokio::{net::UdpSocket, sync::Mutex};

#[derive(Debug, Clone)]
struct ConnectionInfo {
    sender: tokio::sync::mpsc::Sender<Vec<u8>>,
}

pub struct Transport {
    socket: Arc<UdpSocket>,
    connections: Mutex<HashMap<String, ConnectionInfo>>,
    remove_channel_sender: tokio::sync::mpsc::UnboundedSender<String>,
    stop_receive_token: tokio_util::sync::CancellationToken,
}

pub struct Connection {
    transport: Arc<Transport>,
    remote_address: String,
    receiver: Mutex<tokio::sync::mpsc::Receiver<Vec<u8>>>,
}

impl Transport {
    async fn read_from_socket_loop(
        socket: Arc<UdpSocket>,
        stop_receive_token: tokio_util::sync::CancellationToken,
        self_weak: std::sync::Weak<Transport>,
    ) -> Result<()> {
        loop {
            let mut buf = vec![0u8; 1024];
            let (n, addr) = {
                tokio::select! {
                    recv_resp = socket.recv_from(&mut buf) => recv_resp,
                    _ = stop_receive_token.cancelled() => break
                }
            }?;
            buf.resize(n, 0);
            let self_strong = self_weak
                .upgrade()
                .context("weakpointer to self is gone - just stop")?;
            let cons = self_strong.connections.lock().await;
            if let Some(c) = cons.get(&addr.to_string()) {
                _ = c.sender.send(buf).await;
            }
        }
        Ok(())
    }

    async fn read_from_delete_queue_loop(
        mut remove_channel_receiver: tokio::sync::mpsc::UnboundedReceiver<String>,
        self_weak: std::sync::Weak<Transport>,
    ) -> Result<()> {
        loop {
            let to_remove = remove_channel_receiver.recv().await;
            match to_remove {
                Some(to_remove) => {
                    if to_remove.is_empty() {
                        break;
                    }
                    let self_strong = self_weak
                        .upgrade()
                        .context("weak to self is gone - just stop")?;
                    let mut cons = self_strong.connections.lock().await;
                    _ = cons.remove(&to_remove);
                }
                None => break,
            }
        }
        Ok(())
    }

    pub async fn new(local: &str) -> Result<Arc<Self>> {
        let socket = UdpSocket::bind(local).await?;
        let (remove_channel_sender, remove_channel_receiver) =
            tokio::sync::mpsc::unbounded_channel();
        let stop_receive_token = tokio_util::sync::CancellationToken::new();
        let stop_receive_token_child = stop_receive_token.child_token();
        let o = Arc::new(Self {
            socket: Arc::new(socket),
            connections: Mutex::new(HashMap::new()),
            remove_channel_sender,
            stop_receive_token,
        });
        let self_weak = Arc::downgrade(&o.clone());
        let socket = o.socket.clone();
        tokio::spawn(async move {
            _ = Self::read_from_socket_loop(socket, stop_receive_token_child, self_weak).await;
        });
        let self_weak = Arc::downgrade(&o.clone());
        tokio::spawn(async move {
            _ = Self::read_from_delete_queue_loop(remove_channel_receiver, self_weak).await;
        });
        Ok(o)
    }

    pub async fn create_connection(self: &Arc<Self>, remote: &str) -> Arc<Connection> {
        let mut clock = self.connections.lock().await;
        let (sender, receiver) = tokio::sync::mpsc::channel(32);
        clock.insert(remote.to_owned(), ConnectionInfo { sender });
        Arc::new(Connection {
            transport: self.clone(),
            remote_address: remote.to_owned(),
            receiver: Mutex::new(receiver),
        })
    }
}

impl Connection {
    pub async fn send(&self, data: &[u8]) -> Result<()> {
        self.transport
            .socket
            .send_to(data, &self.remote_address)
            .await?;
        Ok(())
    }
    pub async fn receive(&self, timeout: Duration) -> Result<Vec<u8>> {
        let mut ch = self.receiver.lock().await;
        let rec_future = ch.recv();
        let with_timeout = tokio::time::timeout(timeout, rec_future);
        with_timeout.await?.context("eof")
    }
}

impl Drop for Transport {
    fn drop(&mut self) {
        _ = self.remove_channel_sender.send("".to_owned());
        self.stop_receive_token.cancel();
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        _ = self
            .transport
            .remove_channel_sender
            .send(self.remote_address.clone());
    }
}
