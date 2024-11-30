from result import Ok, Err, Result
import socket
from typing import Tuple


class UdpSocket:
    sock: socket.socket
    host: str
    port: int

    def create(self) -> Result[None, str]:
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            return Ok(None)
        except socket.error as e:
            return Err(e.strerror)
        except:
            return Err("An error occured while creating the socket.")

    def set_auto_host_and_port(self) -> Result[None, str]:
        try:
            self.sock.connect(("8.8.8.8", 80))
            self.host, self.port = self.sock.getsockname()
            return Ok(None)
        except socket.error as e:
            return Err(e.strerror)

    def bind(self, ip: str, port: int) -> Result[None, Exception | str]:
        try:
            self.sock.bind((ip, port))
            return Ok(None)
        except socket.error as e:
            return Err(e.strerror)
        except Exception as e:
            return Err(e)

    def send(self, data: bytes, ip: str, port: int) -> Result[None, Exception | str]:
        try:
            self.sock.sendto(data, (ip, port))
            return Ok(None)
        except socket.error as e:
            return Err(e.strerror)
        except Exception as e:
            return Err(e)

    def recv(self, buf: int) -> Result[Tuple[bytes, Tuple[str, int]], Exception | str]:
        try:
            data, addr = self.sock.recvfrom(buf)
            return Ok((data, addr))
        except socket.error as e:
            return Err(e.strerror)
        except Exception as e:
            return Err(e)

    def settimeout(self, timeout: int) -> Result[None, Exception | str]:
        try:
            data, addr = self.sock.settimeout(timeout)
            return Ok(None)
        except socket.error as e:
            return Err(e.strerror)
        except Exception as e:
            return Err(e)

    def close(self) -> Result[None, str]:
        try:
            self.sock.close()
            return Ok(None)
        except socket.error as e:
            return Err(e.strerror)
        except:
            return Err("An error occured while closing the socket.")
