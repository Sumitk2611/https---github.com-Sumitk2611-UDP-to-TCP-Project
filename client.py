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
    last_sequence = 300
    last_acknowledgement = 0
    expected_sequence = last_sequence

    def __init__(self, host: str, port: int) -> None:
        self.server_host = host
        self.server_port = port

        self.sock = UdpSocket()
        self.machine = GraphMachine(
            model=self, states=TcpClient.states, initial="CLOSED"
        )

        self.machine.add_transition("s_send_syn", "CLOSED", "SYN_SENT")
        self.machine.add_transition("s_recv_syn_ack", "SYN_SENT", "SYN_ACK_RECVD")
        self.machine.add_transition(
            "s_establish_connection", "SYN_ACK_RECVD", "ESTABLISHED"
        )
        self.machine.add_transition("s_close", "ESTABLISHED", "CLOSED")

        self.get_graph().draw("client_state_diagram.png", prog="dot")

    def __send_syn_packet(self) -> Result[None, str]:
        packet = TcpPacket(
            flags=TcpFlags(SYN=True),
            sequence=self.last_sequence,
            acknowledgement=self.last_acknowledgement,
            data="",
        )
        self.last_sequence += 1
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
            return Ok(packet)
        if packet.flags.RST:
            return Err("Server Sent a RST Packet. Terminating Connection")

        return Err(f"Expected a syn-ack packet, recieved {packet}")

    def __send_ack_packet(self) -> Result[None, str]:
        packet = TcpPacket(
            flags=TcpFlags(ACK=True),
            sequence=self.last_sequence,
            acknowledgement=self.last_acknowledgement,
            data="",
        )
        b_packet = packet.to_bin()

        send_result = self.sock.send(b_packet, self.server_host, self.server_port)
        if is_err(send_result):
            return send_result

        return Ok(None)

    def __send_data_packet(self, data) -> Result[None, str]:
        packet = TcpPacket(
            flags=TcpFlags(PSH=True, ACK=True),
            sequence=self.last_sequence,
            acknowledgement=self.last_acknowledgement,
            data=data,
        )
        self.expected_sequence = self.last_sequence + len(data)
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
            return Ok(packet)
        if packet.flags.RST:
            return Err("Server Sent a RST Packet. Terminating Connection")

        return Err(f"Expected a ACK packet, recieved {packet}")

    def __recv_fin_packet(self) -> Result[None, str]:
        recv_result = self.sock.recv(1024)
        if is_err(recv_result):
            return recv_result

        (raw_data, _) = recv_result.ok_value
        packet: TcpPacket = TcpPacket.from_bin(raw_data)
        if packet.flags.FIN:
            return Ok(packet)
        if packet.flags.RST:
            return Err("Server Sent a RST Packet. Terminating Connection")

        return Err(f"Expected a FIN packet, recieved {packet}")

    def __send_fin_packet(self) -> Result[None, str]:
        packet = TcpPacket(
            flags=TcpFlags(FIN=True),
            sequence=self.last_sequence,
            acknowledgement=self.last_acknowledgement,
            data="",
        )
        self.expected_sequence = self.last_sequence
        b_packet = packet.to_bin()

        send_result = self.sock.send(b_packet, self.server_host, self.server_port)
        if is_err(send_result):
            return send_result
        return Ok(None)

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
        self.last_acknowledgement = recv_result.ok_value.sequence + 1

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

        if self.expected_sequence == recv_result.ok_value.acknowledgement:
            self.last_sequence = recv_result.ok_value.acknowledgement

        return Ok(None)

    def close_connection(self) -> Result[None, str]:
        send_result = self.__send_fin_packet()
        if is_err(send_result):
            return send_result

        recv_result = self.__recv_ack_packet()
        if is_err(recv_result):
            return recv_result

        if self.expected_sequence == recv_result.ok_value.acknowledgement:
            self.last_sequence = recv_result.ok_value.acknowledgement

        recv_result = self.__recv_fin_packet()
        if is_err(recv_result):
            return recv_result
        if self.expected_sequence == recv_result.ok_value.acknowledgement:
            self.last_sequence = recv_result.ok_value.acknowledgement

        send_result = self.__send_ack_packet()
        if is_err(send_result):
            return send_result
        self.s_close()


def main():
    server_ip , server_port, timeout = argument_parser()
    client = TcpClient(host=server_ip, port=server_port)

    connect_result = client.connect()
    if is_err(connect_result):
        print(connect_result.err())
        exit(-1)

    try:
        while True:
            message = input("You: ")
            result = client.send_message(data=message)
            if is_err(result):
                raise Exception(result.err_value)
    except KeyboardInterrupt:
        print("\nExiting...")
        client.close_connection()
        exit()
    except Exception as e:
        print(e)
        exit()


if __name__ == "__main__":
    main()
