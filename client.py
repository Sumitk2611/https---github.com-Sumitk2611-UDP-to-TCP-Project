import argparse
from result import Ok, Err, Result, is_ok, is_err
from transitions import Machine
from udp_socket import UdpSocket
from packet import TcpPacket, TcpFlags
import time
from transitions.extensions import GraphMachine


def argument_parser():
    """Parse command-line arguments for IP and port."""
    parser = argparse.ArgumentParser(description="Client Side")
    parser.add_argument(
        "--target-port", required=True, type=int, help="Server Port Number"
    )
    parser.add_argument("--target-ip", required=True, help="Server IP Address")
    parser.add_argument("--timeout", required=True, help="Timeout in seconds")
    args = parser.parse_args()

    return (args.target_ip, args.target_port, args.timeout)


class TcpClient:
    sock: UdpSocket
    machine: Machine
    server_host: str
    server_port: int

    states = ["CLOSED", "SYN_SENT", "SYN_ACK_RECVD", "ESTABLISHED"]

    def __init__(self, host: str, port: int) -> None:
        self.server_host = host
        self.server_port = port

        self.sock = UdpSocket()
        self.machine = GraphMachine(model=self, states=TcpClient.states, initial="CLOSED")

        self.machine.add_transition("s_send_syn", "CLOSED", "SYN_SENT")
        self.machine.add_transition("s_recv_syn_ack", "SYN_SENT", "SYN_ACK_RECVD")
        self.machine.add_transition(
            "s_establish_connection", "SYN_ACK_RECVD", "ESTABLISHED"
        )

        self.get_graph().draw('client_state_diagram.png', prog='dot')

    def __send_syn_packet(self) -> Result[None, str]:
        packet = TcpPacket(
            flags=TcpFlags(SYN=True), sequence=0, acknowledgement=1, data=""
        )
        b_packet = packet.to_bin()

        send_result = self.sock.send(b_packet, self.server_host, self.server_port)
        if is_err(send_result):
            return send_result

        return Ok(None)

    def __recv_syn_ack_packet(self) -> Result[None, str]:
        recv_result = self.sock.recv(1024)
        if is_err(recv_result):
            return recv_result

        (raw_data, _) = recv_result.ok_value
        packet: TcpPacket = TcpPacket.from_bin(raw_data)
        if packet.flags.is_syn_ack():
            return Ok(None)

        return Err(f"Expected a syn-ack packet, recieved {packet}")

    def __send_ack_packet(self) -> Result[None, str]:
        packet = TcpPacket(
            flags=TcpFlags(ACK=True), sequence=0, acknowledgement=1, data=""
        )
        b_packet = packet.to_bin()

        send_result = self.sock.send(b_packet, self.server_host, self.server_port)
        if is_err(send_result):
            return send_result

        return Ok(None)
    
    def __send_data_packet(self, data) -> Result [None, str]:
        packet = TcpPacket(
            flags=TcpFlags(PSH=True, ACK=True), sequence=0, acknowledgement=1, data= data
        )
        b_packet = packet.to_bin()

        send_result = self.sock.send(b_packet, self.server_host, self.server_port)
        if is_err(send_result):
            return send_result

        return Ok(None)
    
    def __recv_ack_packet(self) -> Result[None, str]:
        recv_result = self.sock.recv(1024)
        if is_err(recv_result):
            return recv_result

        (raw_data, _) = recv_result.ok_value
        packet: TcpPacket = TcpPacket.from_bin(raw_data)
        if packet.flags.ACK:
            return Ok(None)

        return Err(f"Expected a ACK packet, recieved {packet}")

    def connect(self) -> Result[None, str]:
        create_result = self.sock.create()
        if is_err(create_result):
            return create_result

        send_result = self.__send_syn_packet()
        if is_err(send_result):
            return send_result
        self.s_send_syn()

        recv_result = self.__recv_syn_ack_packet()
        if is_err(recv_result):
            return recv_result
        self.s_recv_syn_ack()

        send_result = self.__send_ack_packet()
        if is_err(send_result):
            return send_result
        self.s_establish_connection()

        return Ok(None)
    
    def send_message(self, data) -> Result[None, str]:
        
        send_result = self.__send_data_packet(data)
        if is_err(send_result):
            return send_result

        recv_result = self.__recv_ack_packet()
        if is_err(recv_result):
            return recv_result
        
        return Ok(None)

def main():
    server_ip = "127.0.0.1"
    server_port = 9000
    #server_ip , server_port, timeout = argument_parser()
    client = TcpClient(host=server_ip, port=server_port)

    connect_result = client.connect()
    if is_err(connect_result):
        print(connect_result.err())
        exit(-1)

    try:
        while True:
            message = input("You: ")
            client.send_message(data=message)
            pass
    except KeyboardInterrupt as e:
        exit()

if __name__ == "__main__":
    main()
