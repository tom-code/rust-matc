use std::net::UdpSocket;
use std::io::Result;



pub struct Transport {
    socket: std::net::UdpSocket,
    remote: String
}


impl Transport {
    pub fn new(remote: &str) -> Self {
        Self {
            socket: UdpSocket::bind("0.0.0.0:5555").unwrap(),
            remote: remote.to_owned()
        }
    }
    pub fn send(&self, data: &[u8]) {
        self.socket.send_to(data, &self.remote).unwrap();
    }

    pub fn receive(&self) -> Result<Vec<u8>>{
        let mut buf = vec![0u8; 1024];
        let (n, _addr) = self.socket.recv_from(&mut buf)?;
        buf.resize(n, 0);
        Ok(buf)
    }
}