from dataclasses import dataclass
from typing import Any
import pickle


@dataclass(init=False)
class TcpFlags:
    SYN: bool = False
    ACK: bool = False
    PSH: bool = False

    def __init__(self, SYN: bool = False, ACK: bool = False, PSH: bool = False) -> None:
        self.SYN = SYN
        self.ACK = ACK
        self.PSH = PSH

        if (not(SYN or ACK or PSH)):
            raise "Atleast one TCP flag needs to be set"
        
    
    def is_syn_ack(self):
        return self.SYN and self.ACK



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