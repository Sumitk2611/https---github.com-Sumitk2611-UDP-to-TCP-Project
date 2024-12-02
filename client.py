import argparse
from result import Ok, Err, Result, is_ok, is_err
from transitions import Machine
from udp_socket import UdpSocket
from packet import TcpPacket, TcpFlags
import socket
import time
from transitions.extensions import GraphMachine
from Graph import Graph


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

    MAX_RETRIES = 5
    INITIAL_TIMEOUT = 10.0  # seconds

    packet_sent_Graph = Graph("Packets Sent From Client")
    packet_retransmission_Graph = Graph("Retransmitted Packets (Client)")
    packet_received_Graph = Graph("Packets Received by Client")

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
        self.machine.add_transition("s_rst", "*", "CLOSED")

        self.get_graph().draw("client_state_diagram.png", prog="dot")

    def __retransmit(self, send_func, recv_func, expected_validation=None):
        timeout = self.INITIAL_TIMEOUT
        retries = 0

        while retries < self.MAX_RETRIES:
            print(f"Attempt {retries + 1}: Sending packet...")

            send_result = send_func()

            #retransmission logic
            if(retries > 0):
                self.packet_retransmission_Graph.add_packet()

            if is_err(send_result):
                return send_result
            
            self.sock.settimeout(timeout)
            recv_result = recv_func()

            if is_ok(recv_result):
                if expected_validation is None or expected_validation(
                    recv_result.ok_value
                ):
                    self.sock.settimeout(None)  # Reset timeout
                    return recv_result

            # If validation fails, treat as timeout and retransmit
            retries += 1
            timeout *= 2  # Exponential backoff

        self.sock.sock.settimeout(None)  # Reset timeout
        return Err("Max retries exceeded - connection failed")

    def __send_syn_packet(self) -> Result[None, str]:
        packet = TcpPacket(
            flags=TcpFlags(SYN=True),
            sequence=self.last_sequence,
            acknowledgement=self.last_acknowledgement,
            data="",
        )
        
        b_packet = packet.to_bin()

        send_result = self.sock.send(b_packet, self.server_host, self.server_port)
        if is_err(send_result):
            return send_result
        
        self.packet_sent_Graph.add_packet()

        return Ok(None)

    def __recv_syn_ack_packet(self) -> Result[None, str]:
        recv_result = self.sock.recv(1024)
        self.packet_received_Graph.add_packet()
        if is_err(recv_result):
            return recv_result

        (raw_data, _) = recv_result.ok_value
        packet: TcpPacket = TcpPacket.from_bin(raw_data)
        if packet.flags.is_syn_ack():
            self.last_sequence = packet.acknowledgement
            return Ok(packet)
        if packet.flags.RST:
            print( "Server Sent a RST Packet. Terminating Connection")
            self.s_rst()
            exit()

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
        self.packet_sent_Graph.add_packet()

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

        self.packet_sent_Graph.add_packet()

        return Ok(None)

    def __recv_ack_packet(self) -> Result[None, str]:
        recv_result = self.sock.recv(1024)
        self.packet_received_Graph.add_packet()

        if is_err(recv_result):
            return recv_result

        (raw_data, _) = recv_result.ok_value
        packet: TcpPacket = TcpPacket.from_bin(raw_data)
        if packet.flags.ACK:
            self.last_sequence = packet.acknowledgement
            return Ok(packet)
        if packet.flags.RST:
            print( "Server Sent a RST Packet. Terminating Connection")
            self.s_rst()
            exit()

        return Err(f"Expected a ACK packet, recieved {packet}")

    def __recv_fin_packet(self) -> Result[None, str]:
        recv_result = self.sock.recv(1024)
        self.packet_received_Graph.add_packet()

        if is_err(recv_result):
            return recv_result

        (raw_data, _) = recv_result.ok_value
        packet: TcpPacket = TcpPacket.from_bin(raw_data)
        if packet.flags.FIN:
            return Ok(packet)
        if packet.flags.RST:
            print( "Server Sent a RST Packet. Terminating Connection")
            self.s_rst()
            exit()

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

        self.packet_sent_Graph.add_packet()

        return Ok(None)

    def connect(self) -> Result[None, str]:
        create_result = self.sock.create()
        if is_err(create_result):
            return create_result

        # Handle SYN-SYNACK-ACK exchange with retransmission
        retransmit_result = self.__retransmit(
            send_func=self.__send_syn_packet,
            recv_func=self.__recv_syn_ack_packet,
            expected_validation=lambda packet: packet.flags.is_syn_ack(),
        )

        if is_err(retransmit_result):
            return retransmit_result

        self.s_send_syn()
        self.s_recv_syn_ack()

        syn_ack_packet = retransmit_result.ok_value
        self.last_acknowledgement = syn_ack_packet.sequence + 1

        # Send final ACK with retransmission
        send_result = self.__send_ack_packet()
        if is_err(send_result):
            return send_result

        self.s_establish_connection()
        return Ok(None)

    def send_message(self, data) -> Result[None, str]:
        def validate_ack(packet):
            return packet.flags.ACK and packet.acknowledgement == self.expected_sequence

        retransmit_result = self.__retransmit(
            send_func=lambda: self.__send_data_packet(data),
            recv_func=self.__recv_ack_packet,
            expected_validation=validate_ack,
        )

        if is_err(retransmit_result):
            return retransmit_result

        ack_packet = retransmit_result.ok_value
        self.last_sequence = ack_packet.acknowledgement
        return Ok(None)

    def close_connection(self) -> Result[None, str]:
        # Send FIN and wait for ACK
        retransmit_result = self.__retransmit(
            send_func=self.__send_fin_packet,
            recv_func=self.__recv_ack_packet,
            expected_validation=lambda packet: (
                packet.flags.ACK and packet.acknowledgement == self.expected_sequence
            ),
        )

        if is_err(retransmit_result):
            return retransmit_result

        ack_packet = retransmit_result.ok_value
        self.last_sequence = ack_packet.acknowledgement

        # Wait for server's FIN
        fin_result = self.__recv_fin_packet()
        if is_err(fin_result):
            return fin_result

        if self.expected_sequence == fin_result.ok_value.acknowledgement:
            self.last_sequence = fin_result.ok_value.acknowledgement

        # Send final ACK
        send_result = self.__send_ack_packet()
        if is_err(send_result):
            return send_result

        self.s_close()
        return Ok(None)

    def display_graphs(self):
        self.packet_sent_Graph.run()
        self.packet_received_Graph.run()
        self.packet_retransmission_Graph.run()

    def destroy_graphs(self):
        self.packet_received_Graph.close()
        self.packet_retransmission_Graph.close()
        self.packet_sent_Graph.close()


def main():
    server_ip, server_port, timeout = argument_parser()
    client = TcpClient(host=server_ip, port=server_port)
    
    connect_result = client.connect()
    if is_err(connect_result):
        print(connect_result.err())
        exit(-1)

    try:
        while True:
            message = input("You: ")
            result = client.send_message(data=message)
            client.display_graphs()
            if is_err(result):
                raise Exception(result.err_value)
    except KeyboardInterrupt:
        print("\nExiting...")
        client.close_connection()
        client.destroy_graphs()
        exit()
    except Exception as e:
        print(e)
        exit()


if __name__ == "__main__":
    main()
