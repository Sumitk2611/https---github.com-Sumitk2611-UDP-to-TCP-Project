import argparse
from udp_socket import UdpSocket
from packet import TcpPacket, TcpFlags
from typing import Dict, Tuple
from transitions import Machine
from result import Ok, Err, Result, is_ok, is_err
from transitions.extensions import GraphMachine
import threading
from Graph import Graph


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

    last_packet_received : TcpPacket = None
    last_packet_sent: TcpPacket = None

    MAX_RETRIES = 5
    retries = 0
    INITIAL_TIMEOUT = 100.0

    timer: threading.Timer

    packet_sent_Graph = Graph("Packets Sent From Server")
    packet_retransmission_Graph = Graph("Retransmitted Packets (Server)")
    packet_received_Graph = Graph("Packets Received by Server")

    def __init__(self, sock: UdpSocket, client_ip: str, client_port: str) -> None:
        self.sock = sock
        self.client_ip = client_ip
        self.client_port = client_port

        self.machine = GraphMachine(
            model=self, states=TcpSession.states, initial="CLOSED"
        )
        self.machine.add_transition("s_syn_recvd", "CLOSED", "SYN_RECVD")
        self.machine.add_transition("s_established", "SYN_RECVD", "ESTABLISHED")
        self.machine.add_transition("s_closed", "ESTABLISHED", "CLOSED")
        self.machine.add_transition("s_rst", "*", "CLOSED")

        self.get_graph().draw("server_state_diagram.png", prog="dot")
        self.timer = None

    def start_timer(self):
        """Start a timer to handle retransmissions."""
        def timeout_handler():    
            # Send the last packet again
            
            self.sock.send(self.last_packet_sent.to_bin(), self.client_ip, self.client_port)
            self.packet_retransmission_Graph.add_packet()
            self.packet_sent_Graph.add_packet()
            self.display_graphs
            # Check if retry count is within limits and restart the timer if necessary
            if self.retries < self.MAX_RETRIES:
                self.start_timer()  # Restart the timer
            else:
                print("Max retries reached. Stopping further retransmissions.")
            return
        
        if self.timer:
            self.timer.cancel()
        
        if self.retries < self.MAX_RETRIES:
            self.retries += 1
            self.INITIAL_TIMEOUT *= self.retries
            self.timer = threading.Timer(self.INITIAL_TIMEOUT, timeout_handler)
            self.timer.start()


    
    def __is_duplicate(self, packet: TcpPacket) -> bool:
        if self.last_packet_received:
            if self.last_packet_received.flags == packet.flags:
                return packet.sequence <= self.last_packet_received.sequence
        return False

    def __send_syn_ack(self) -> Result[None, str]:
        packet = TcpPacket(
            flags=TcpFlags(SYN=True, ACK=True),
            sequence=self.last_sequence,
            acknowledgement=self.last_acknowledgement,
            data="",
        )
        self.last_packet_sent = packet
        self.last_sequence += 1
        b_packet = packet.to_bin()
        print("Sending Syn ack")
        send_result = self.sock.send(b_packet, self.client_ip, self.client_port)
        if is_ok(send_result):
            print("packet sent")
        self.packet_sent_Graph.add_packet()
        if is_ok(send_result):
            self.start_timer()

        return send_result

    def __send_ack(self) -> Result[None, str]:
        packet = TcpPacket(
            flags=TcpFlags(ACK=True),
            sequence=self.last_sequence,
            acknowledgement=self.last_acknowledgement,
            data="",
        )
        self.last_packet_sent = packet
        b_packet = packet.to_bin()
        self.packet_sent_Graph.add_packet()

        # Send the packet
        send_result = self.sock.send(b_packet, self.client_ip, self.client_port)

        # Start timer after sending the ACK packet
        if is_ok(send_result):
            self.start_timer()

        return send_result

    def __send_fin(self) -> Result[None, str]:
        packet = TcpPacket(
            flags=TcpFlags(FIN=True),
            sequence=self.last_sequence,
            acknowledgement=self.last_acknowledgement,
            data="",
        )
        self.last_packet_sent = packet
        b_packet = packet.to_bin()
        self.packet_sent_Graph.add_packet()

        send_result = self.sock.send(b_packet, self.client_ip, self.client_port)

        if is_ok(send_result):
            self.start_timer()

        return send_result


    def __send_rst(self) -> Result[None, str]:
        packet = TcpPacket(
            flags=TcpFlags(RST=True),
            sequence=self.last_sequence,
            acknowledgement=self.last_acknowledgement,
            data="",
        )
        self.last_packet_sent = packet
        b_packet = packet.to_bin()
        self.packet_sent_Graph.add_packet()
        # Send the packet
        send_result = self.sock.send(b_packet, self.client_ip, self.client_port)
        
        return send_result
    def __close(self) -> Result[None, Exception | str]:
        send_result = self.__send_ack()
        if is_err(send_result):
            return send_result

        send_result = self.__send_fin()
        if is_err(send_result):
            return send_result
        self.s_closed()
        return Ok(None)

    def get_state(self):
        return self.state

    def terminate_connection(self):
        send_result = self.__send_rst()
        if self.timer:
            self.timer.cancel()
        if is_err(send_result):
            return send_result
        self.s_rst()
        return Ok(None)

    def on_packet(self, packet: TcpPacket):
        self.packet_received_Graph.add_packet()
        if self.__is_duplicate(packet):
                self.sock.send(self.last_packet_sent.to_bin(), self.client_ip, self.client_port)
                self.packet_retransmission_Graph.add_packet()
                self.packet_sent_Graph.add_packet()
                self.start_timer()
                return
        
        self.last_packet_received = packet
        self.retries = 0
        
        if self.timer:
            self.timer.cancel()
            
        match self.state:
            case "CLOSED":
                if packet.flags.SYN:
                    self.last_acknowledgement = packet.acknowledgement + 1
                    send_result = self.__send_syn_ack()
                    if is_err(send_result):
                        print( f"An error occured while sending syn ack to {self.client_ip} {self.client_port}")
                        print(send_result.err())

                    self.s_syn_recvd()
            case "SYN_RECVD":
                if packet.flags.ACK:
                    self.__send_ack()
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
        return

    def display_graphs(self):
        self.packet_sent_Graph.run()
        self.packet_received_Graph.run()
        self.packet_retransmission_Graph.run()

    def destroy_graphs(self):
        self.packet_received_Graph.close()
        self.packet_retransmission_Graph.close()
        self.packet_sent_Graph.close()

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
            #print(cpacket)
            if addr in connections.keys():
                session = connections.get(addr)
            else:
                session = TcpSession(sock, addr[0], addr[1])
                connections[addr] = session
            print(cpacket)
            session.on_packet(cpacket)
            session.display_graphs()
    except KeyboardInterrupt as e:
        for addr, session in connections.items():
            if session.get_state() == "CLOSED":
                continue
            print(f"Processing session for {addr}")
            session.terminate_connection()
        
        print("Destroying Graph Windows")
        session.destroy_graphs()
        exit()


if __name__ == "__main__":
    main()
