import argparse
from udp_socket import UdpSocket
from packet import TcpPacket, TcpFlags
from typing import Dict, Tuple
from transitions import Machine
from result import Ok, Err, Result, is_ok, is_err
from transitions.extensions import GraphMachine


def argument_parser():
    parser = argparse.ArgumentParser(description="Server Side")
    parser.add_argument(
        "--listen-port", required=True, type=int, help="Port to listen on "
    )
    parser.add_argument("--listen-ip", required=True, help="IP Address to bind to")
    args = parser.parse_args()
    return (args.listen_ip, args.listen_port)


class TcpSession:
    sock: UdpSocket
    machine: Machine
    client_ip: str
    client_port: str

    states = ["CLOSED", "SYN_RECVD", "ESTABLISHED"]

    last_sequence = 100
    last_acknowledgement = 1

    def __init__(self, sock: UdpSocket, client_ip: str, client_port: str) -> None:
        self.sock = sock
        self.client_ip = client_ip
        self.client_port = client_port

        self.machine = GraphMachine(model=self, states=TcpSession.states, initial="CLOSED")
        self.machine.add_transition("s_syn_recvd", "CLOSED", "SYN_RECVD")
        self.machine.add_transition("s_established", "SYN_RECVD", "ESTABLISHED")

        self.get_graph().draw('server_state_diagram.png', prog='dot')

    def __send_syn_ack(self) -> Result[None, Exception | str]:
        packet = TcpPacket(
            flags=TcpFlags(SYN=True, ACK=True), sequence=self.last_sequence, acknowledgement=self.last_acknowledgement, data=""
        )
        self.last_sequence +=1
        b_packet = packet.to_bin()

        send_result = self.sock.send(b_packet, self.client_ip, self.client_port)
        if is_err(send_result):
            return send_result

        return Ok(None)
    
    def __send_ack(self) -> Result[None, Exception | str]:
        packet = TcpPacket(
            flags=TcpFlags(ACK=True), sequence=self.last_sequence, acknowledgement=self.last_acknowledgement, data=""
        )
        b_packet = packet.to_bin()

        send_result = self.sock.send(b_packet, self.client_ip, self.client_port)
        if is_err(send_result):
            return send_result

        return Ok(None)

    def on_packet(self, packet: TcpPacket):
        match self.state:
            case "CLOSED":
                if packet.flags.SYN:
                    self.last_acknowledgement = packet.acknowledgement+1
                    send_result = self.__send_syn_ack()
                    if is_err(send_result):
                        print(f"An error occured while sending syn ack to {self.client_ip} {self.client_port}")
                        print(send_result.err())

                    self.s_syn_recvd()
            case "SYN_RECVD":
                if packet.flags.ACK:
                    self.s_established()
                    print(f"Connection established {self.client_ip} {self.client_port}")
            
            case "ESTABLISHED":
                if packet.flags.is_psh_ack():
                    print(packet.data)
                    self.last_acknowledgement = packet.sequence + len(packet.data)
                    send_result = self.__send_ack()
                    if is_err(send_result):
                        print(f"An error occured while sending ack to {self.client_ip} {self.client_port}")
                        print(send_result.err())

        return


def main():
    ip, port = argument_parser()

    sock = UdpSocket()
    sock.create()
    sock.bind(ip, port)

    connections: Dict[Tuple[str, int], TcpSession] = {}

    while True:
        data, addr = sock.recv(1024).ok_value
        cpacket: TcpPacket = TcpPacket.from_bin(data)
        print(cpacket)
        if addr in connections.keys():
            session = connections.get(addr)
            session.on_packet(cpacket)
        else:
            session = TcpSession(sock, addr[0], addr[1])
            connections[addr] = session
            session.on_packet(cpacket)


if __name__ == "__main__":
    main()
    