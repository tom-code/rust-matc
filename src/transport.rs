use anyhow::Result;
use std::collections::HashMap;
use std::net::UdpSocket;
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::Duration;

struct ConnectionInfo {
    sender: mpsc::Sender<Vec<u8>>,
}

pub struct Transport {
    socket: std::net::UdpSocket,
    connections: Mutex<HashMap<String, ConnectionInfo>>,
}

pub struct Connection {
    transport: Arc<Transport>,
    remote_address: String,
    receiver: Mutex<mpsc::Receiver<Vec<u8>>>,
}

impl Transport {
    pub fn new(local: &str) -> Result<Arc<Self>> {
        let socket = UdpSocket::bind(local)?;
        socket.set_read_timeout(Some(Duration::from_secs(3)))?;
        let o = Arc::new(Self {
            socket,
            connections: Mutex::new(HashMap::new()),
        });
        let self_c = o.clone();
        thread::spawn(move || loop {
            let mut buf = vec![0u8; 1024];
            let (n, addr) = self_c.socket.recv_from(&mut buf).unwrap();
            buf.resize(n, 0);
            let cons = self_c.connections.lock().unwrap();
            if let Some(c) = cons.get(&addr.to_string()) {
                c.sender.send(buf).unwrap();
            }
        });
        Ok(o)
    }

    pub fn create_connection(self: &Arc<Self>, remote: &str) -> Arc<Connection> {
        let mut clock = self.connections.lock().unwrap();
        let (sender, receiver) = mpsc::channel();
        clock.insert(remote.to_owned(), ConnectionInfo { sender });
        Arc::new(Connection {
            transport: self.clone(),
            remote_address: remote.to_owned(),
            receiver: Mutex::new(receiver),
        })
    }
}

impl Connection {
    pub fn send(&self, data: &[u8]) {
        self.transport
            .socket
            .send_to(data, &self.remote_address)
            .unwrap();
    }
    pub fn receive(&self) -> Result<Vec<u8>> {
        let ch = self.receiver.lock().unwrap();
        Ok(ch.recv()?)
    }
}
