import socket
import argparse
import json

TCP_handshake = False

def argument_parser():
    """Parse command-line arguments for IP and port."""
    port = 5000
    parser = argparse.ArgumentParser(description="Client Side")
    parser.add_argument( "--target-port", required=True, type=int, help="Server Port Number")
    parser.add_argument("--target-ip", required=True, help="Server IP Address")
    parser.add_argument("--timeout", required=True, help="Timeout in seconds")
    args = parser.parse_args()

    return ((args.target_ip, args.target_port),args.timeout)
    
def create_socket():
    """Create a UDP socket."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return s
    except socket.error as e:
        print(f"Unable to create socket due to Error: {e}")
        raise e

def send_message(socket_fd, data, ip_port_tuple):
    """Send a message to the server."""
    try:
        socket_fd.sendto(data.encode('utf-8'), ip_port_tuple)
    except socket.error as e:
        print(f"Unable to send data due to Error: {e}")
        raise e

def receive_message(socket_fd, buffer_size=1024):
    """Receive a message from the server."""
    try:
        data, _ = socket_fd.recvfrom(buffer_size)
        return data.decode('utf-8')
    except socket.error as e:
        print(f"Unable to receive data due to Error: {e}")
        raise e

def close_socket(socket_fd):
    """Close the socket."""
    try:
        socket_fd.close()
    except socket.error as e:
        print(f"Error closing socket: {e}")
        raise e

def create_packet(data,sequence, acknowledgement, flags=[]):
    new_packet = {
        "flags": flags,
        "sequence": sequence,
        "acknowledgement": acknowledgement,
        "data": data
    }
    return json.dumps(new_packet)

def create_connection(socket_fd, ip_port_tuple):
    send_SYN_packet(socket_fd, ip_port_tuple)
    if received_SYN_ACK_packet(socket_fd):
        send_ACK_packet(socket_fd, ip_port_tuple)
        return True
def send_SYN_packet(socket_fd, ip_port_tuple):
    packet = create_packet("", 0, 1, ["SYN"])
    print("Sending SYN Packet")
    send_message(socket_fd, packet, ip_port_tuple)

def received_SYN_ACK_packet(socket_fd):
    packet_json = wait_for_packet(socket_fd)
    if(len(packet_json['flags']) == 2 and packet_json['flags'][0]=="SYN" and packet_json['flags'][1]=="ACK"):
        print("Received SYN ACK Packet")
        return True

def send_ACK_packet(socket_fd, ip_port_tuple):
    res_packet = create_packet("", sequence=0, acknowledgement=1, flags=["ACK"])
    print("Sending ACK")
    send_message(socket_fd, res_packet, ip_port_tuple)
    
def wait_for_packet(socket_fd):
    packet_string = receive_message(socket_fd)
    packet_json = json.loads(packet_string)
    return packet_json

def main():
    TCP_handshake = False
    ip_port_tuple, timeout = argument_parser()

    try:
        s = create_socket()
    except socket.error:
        exit(1)

    try:
        print("UDP Client Started. Type your messages below:")
        while True:
            try:
                if not TCP_handshake:
                    TCP_handshake = create_connection(s, ip_port_tuple)
                    
                if TCP_handshake:
                    # Send a message to the server
                    message = input("You: ")
                    send_message(s, message, ip_port_tuple)

            except KeyboardInterrupt:
                print("\nShutting down client.")
                break
    finally:
        close_socket(s)
        print("Client shut down")

if __name__ == "__main__":
    main()



