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

    states = ["CLOSED", "SYN_RECVD", "ESTABLISHED", "LAST_ACK"]

    last_sequence = 100
    last_acknowledgement = 1

    last_valid_sequence: int = None
    last_valid_acknowledgement: int = None

    MAX_RETRIES = 10
    INITIAL_TIMEOUT = 1.0 

    def __init__(self, sock: UdpSocket, client_ip: str, client_port: str) -> None:
        self.sock = sock
        self.client_ip = client_ip
        self.client_port = client_port

        self.machine = GraphMachine(
            model=self, states=TcpSession.states, initial="CLOSED"
        )
        self.machine.add_transition("s_syn_recvd", "CLOSED", "SYN_RECVD")
        self.machine.add_transition("s_established", "SYN_RECVD", "ESTABLISHED")
        self.machine.add_transition("s_wait_for_ack", "ESTABLISHED", "LAST_ACK")
        self.machine.add_transition("s_closed", "LAST_ACK", "CLOSED")
        self.machine.add_transition("s_rst", "*", "CLOSED")

        self.get_graph().draw("server_state_diagram.png", prog="dot")



    def __retransmit(self, send_func, recv_func=None, expected_validation=None) -> Result[None, str]:
        timeout = self.INITIAL_TIMEOUT
        retries = 0

        while retries < self.MAX_RETRIES:
            send_result = send_func()
            if is_err(send_result):
                return send_result

            if recv_func:
                self.sock.settimeout(timeout)
                recv_result = recv_func()

                if is_ok(recv_result):
                    if expected_validation is None or expected_validation(recv_result.ok_value):
                        if not self.__is_duplicate(recv_result.ok_value):  # Ensure no duplicates
                            self.sock.settimeout(None)
                            return recv_result

            retries += 1
            timeout *= 2  # Exponential backoff

        self.sock.settimeout(None)  # Reset timeout
        return Err("Max retries exceeded - operation failed")

    def __is_duplicate(self, packet: TcpPacket) -> bool:
        
        if self.last_valid_sequence is not None:
            return packet.sequence <= self.last_valid_acknowledgement
        return False


    def __send_syn_ack(self) -> Result[None, str]:
        def send_func():
            packet = TcpPacket(
                flags=TcpFlags(SYN=True, ACK=True),
                sequence=self.last_sequence,
                acknowledgement=self.last_acknowledgement,
                data="",
            )
            self.last_sequence += 1
            b_packet = packet.to_bin()
            return self.sock.send(b_packet, self.client_ip, self.client_port)

        def recv_func():
            try:
                data, addr = self.sock.recv(1024).ok_value
                received_packet = TcpPacket.from_bin(data)

                # Check for duplicate packets
                if self.__is_duplicate(received_packet):
                    print(f"Ignoring duplicate packet from {addr[0]}:{addr[1]}")
                    return Err("Duplicate packet received")

                # Validate the incoming ACK packet
                if (
                    received_packet.flags.ACK
                    and received_packet.acknowledgement == self.last_sequence
                ):
                    # Update valid sequence/acknowledgment numbers
                    
                    self.last_valid_acknowledgement = received_packet.sequence
                    return Ok(received_packet)
                else:
                    return Err("Unexpected or invalid ACK received")
            except Exception as e:
                return Err(f"Error receiving ACK: {e}")


        # Use __retransmit to send SYN-ACK and wait for a valid ACK
        return self.__retransmit(send_func=send_func, recv_func=recv_func)


    def __send_ack(self) -> Result[None, str]:
        def send_func():
            packet = TcpPacket(
                flags=TcpFlags(ACK=True),
                sequence=self.last_sequence,
                acknowledgement=self.last_acknowledgement,
                data="",
            )
            b_packet = packet.to_bin()
            return self.sock.send(b_packet, self.client_ip, self.client_port)

        def recv_func():
            try:
                data, addr = self.sock.recv(1024).ok_value
                received_packet = TcpPacket.from_bin(data)

                # Check for duplicate packets
                if self.__is_duplicate(received_packet):
                    print(f"Ignoring duplicate packet from {addr[0]}:{addr[1]}")
                    return Err("Duplicate packet received")

                # Validate the ACK packet
                if (
                    received_packet.flags.ACK
                    and received_packet.acknowledgement == self.last_sequence
                ):
                    # Update valid sequence/acknowledgment numbers
                    
                    self.last_valid_acknowledgement = received_packet.sequence
                    return Ok(received_packet)
                else:
                    return Err("Unexpected or invalid ACK received")
            except Exception as e:
                return Err(f"Error receiving ACK: {e}")

        return self.__retransmit(send_func=send_func, recv_func=recv_func)


    def __send_fin(self) -> Result[None, str]:
        def send_func():
            packet = TcpPacket(
                flags=TcpFlags(FIN=True),
                sequence=self.last_sequence,
                acknowledgement=self.last_acknowledgement,
                data="",
            )
            b_packet = packet.to_bin()
            return self.sock.send(b_packet, self.client_ip, self.client_port)

        return self.__retransmit(send_func=send_func)

    def __send_rst(self) -> Result[None, Exception | str]:
        packet = TcpPacket(
            flags=TcpFlags(RST=True),
            sequence=self.last_sequence,
            acknowledgement=self.last_acknowledgement,
            data="",
        )
        b_packet = packet.to_bin()

        send_result = self.sock.send(b_packet, self.client_ip, self.client_port)
        if is_err(send_result):
            return send_result

        return Ok(None)

    def __close(self) -> Result[None, Exception | str]:
        send_result = self.__send_ack()
        if is_err(send_result):
            return send_result

        send_result = self.__send_fin()
        if is_err(send_result):
            return send_result
        self.s_wait_for_ack()
        return Ok(None)

    def get_state(self):
        return self.state

    def terminate_connection(self):
        send_result = self.__send_rst()

        if is_err(send_result):
            return send_result
        self.s_rst()
        return Ok(None)

    def on_packet(self, packet: TcpPacket):

        if self.__is_duplicate(packet):
                print(f"Ignoring duplicate packet from {self.client_ip}:{self.client_port}")                
                if packet.flags.SYN:
                    print(f"Retransmitting SYN-ACK for duplicate SYN from {self.client_ip}:{self.client_port}")
                    self.__send_syn_ack()
                else:
                    # Optionally, acknowledge other duplicate packets
                    self.__send_ack()
                return

        match self.state:
            case "CLOSED":
                if packet.flags.SYN:
                    self.last_valid_acknowledgement = packet.sequence
                    self.last_acknowledgement = packet.acknowledgement + 1
                    send_result = self.__send_syn_ack()
                    if is_err(send_result):
                        print( f"An error occured while sending syn ack to {self.client_ip} {self.client_port}")
                        print(send_result.err())

                    self.s_syn_recvd()
            case "SYN_RECVD":
                if packet.flags.SYN:
                    # Retransmit
                    self.last_acknowledgement = packet.acknowledgement + 1
                    send_result = self.__send_syn_ack()
                    if is_err(send_result):
                        print( f"An error occured while sending syn ack to {self.client_ip} {self.client_port}")
                        print(send_result.err())

                if packet.flags.ACK:
                    self.s_established()
                    print(f"Connection established {self.client_ip} {self.client_port}")

            case "ESTABLISHED":
                if packet.flags.is_psh_ack():
                    print(f"Client {self.client_ip}: {packet.data}")
                    self.last_acknowledgement = packet.sequence + len(packet.data)
                    send_result = self.__send_ack()
                    if is_err(send_result):
                        print(
                            f"An error occured while sending ack to {self.client_ip} {self.client_port}"
                        )
                        print(send_result.err())

                elif packet.flags.FIN:
                    print("Received FIN Packet closing connection")
                    self.last_acknowledgement = packet.sequence + len(packet.data)
                    send_result = self.__close()
                    if is_err(send_result):
                        return send_result

            case "LAST_ACK":
                if packet.flags.ACK:
                    self.s_closed()
                    print(f"Terminated Connection {self.client_ip} {self.client_port}")
        return


def main():
    ip, port = argument_parser()

    sock = UdpSocket()
    sock.create()
    sock.bind(ip, port)

    connections: Dict[Tuple[str, int], TcpSession] = {}
    try:
        while True:
            data, addr = sock.recv(1024).ok_value
            cpacket: TcpPacket = TcpPacket.from_bin(data)
            print(cpacket)
            if addr in connections.keys():
                session = connections.get(addr)
            else:
                session = TcpSession(sock, addr[0], addr[1])
                connections[addr] = session

            session.on_packet(cpacket)
    except KeyboardInterrupt as e:
        for addr, session in connections.items():
            if session.get_state() == "CLOSED":
                continue
            print(f"Processing session for {addr}")
            session.terminate_connection()


if __name__ == "__main__":
    main()
