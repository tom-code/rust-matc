use anyhow::Result;
use std::{collections::HashMap, sync::Arc, time::Duration};
use tokio::{net::UdpSocket, sync::Mutex};

struct ConnectionInfo {
    sender: tokio::sync::mpsc::Sender<Vec<u8>>,
}

pub struct Transport {
    socket: UdpSocket,
    connections: Mutex<HashMap<String, ConnectionInfo>>,
}

pub struct Connection {
    transport: Arc<Transport>,
    remote_address: String,
    receiver: Mutex<tokio::sync::mpsc::Receiver<Vec<u8>>>,
}

impl Transport {
    pub async fn new(local: &str) -> Result<Arc<Self>> {
        let socket = UdpSocket::bind(local).await?;
        let o = Arc::new(Self {
            socket,
            connections: Mutex::new(HashMap::new()),
        });
        let self_c = o.clone();
        tokio::spawn(async move {
            loop {
                let mut buf = vec![0u8; 1024];
                let (n, addr) = self_c.socket.recv_from(&mut buf).await.unwrap();
                buf.resize(n, 0);
                let cons = self_c.connections.lock().await;
                if let Some(c) = cons.get(&addr.to_string()) {
                    c.sender.send(buf).await.unwrap();
                }
            }
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
    pub async fn receive(&self) -> Result<Vec<u8>> {
        let mut ch = self.receiver.lock().await;
        let rec_future = ch.recv();
        let with_timeout = tokio::time::timeout(Duration::from_secs(3), rec_future);
        let res = match with_timeout.await {
            Ok(res) => res,
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "error waiting for data from transport err:{}",
                    e
                ))
            }
        };
        match res {
            Some(r) => Ok(r),
            None => Err(anyhow::anyhow!("channel eof")),
        }
    }
}

impl Drop for Transport {
    fn drop(&mut self) {
        println!("drop transport");
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        println!("drop connection");
    }
}
