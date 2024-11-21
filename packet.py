from dataclasses import dataclass
from typing import Any
import pickle


@dataclass(init=False)
class TcpFlags:
    SYN: bool = False
    ACK: bool = False
    PSH: bool = False
    FIN: bool = False
    RST: bool = False

    def __init__(self, SYN: bool = False, ACK: bool = False, PSH: bool = False, FIN: bool = False, RST: bool = False) -> None:
        self.SYN = SYN
        self.ACK = ACK
        self.PSH = PSH
        self.FIN = FIN
        self.RST = RST

        if (not(SYN or ACK or PSH or FIN or RST)):
            raise "Atleast one TCP flag needs to be set"
        
    
    def is_syn_ack(self):
        return self.SYN and self.ACK
    
    def is_psh_ack(self):
        return self.PSH and self.ACK



@dataclass(init=True)
class TcpPacket:
    flags: TcpFlags
    sequence: int
    acknowledgement: int
    data: str

    def to_bin(self) -> bytes:
        return pickle.dumps(self)

    def from_bin(data: bytes):
        return pickle.loads(data)