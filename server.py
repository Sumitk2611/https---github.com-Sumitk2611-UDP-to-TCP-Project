import socket
import argparse
import json

def argument_parser():
    parser = argparse.ArgumentParser(description="Server Side")
    parser.add_argument( "--listen-port", required=True, type = int , help="Port to listen on ")
    parser.add_argument( "--listen-ip", required=True, help="IP Address to bind to")
    args = parser.parse_args()
    return (args.listen_ip,args.listen_port)

def create_socket():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return s
    except socket.error as e:
        print(f"Unable to create socket due to Error: {e}")
        raise e

def close_socket(socket_fd):
    try:
        socket_fd.close()
    except socket.error as e:
        raise e
    
def bind(socket_fd,IP_PORT_TUPLE):
    try:
        socket_fd.bind(IP_PORT_TUPLE)
    except socket.error as e:
        print(f"Unable to bind socket due to Error: {e}")
        raise e

def send_message(socket_fd, data, ip_port_tuple):
    """Send a message to the server."""
    try:
        socket_fd.sendto(data.encode('utf-8'), ip_port_tuple)
    except socket.error as e:
        print(f"Unable to send data due to Error: {e}")
        raise e

def receive_message(socket_fd):
    try:
        data, client_address = socket_fd.recvfrom(1024)  # Receive up to 1024 bytes
        return data.decode('utf-8'), client_address
    except socket.error as e:
        print(f"Error receiving message: {e}")
        raise e

def create_packet(data,sequence, acknowledgement, flags=[]):
    try:
        new_packet = {
            "flags": flags,
            "sequence": sequence,
            "acknowledgement": acknowledgement,
            "data": data
        }
        return json.dumps(new_packet)
    except:
        print("Unable to create packet")
        raise RuntimeError("Failed to Create Packet")
        

def accept_connection(socket_fd):
    packet_json, client_tuple = received_SYN(socket_fd)
    #received response
    if packet_json:
        send_SYN_ACK_Packet(socket_fd, client_tuple)
        packet_json = received_ACK(socket_fd)
        print("Received ACK")
        print("TCP Handshake Completed")
        return True

def received_SYN(socket_fd):
    packet_json, client_tuple = wait_for_packet(socket_fd)
    if(len(packet_json['flags']) == 1 and packet_json['flags'][0]=="SYN"):
        print("Received SYN Packet")
        return (packet_json, client_tuple)
          
def received_ACK(socket_fd):
    packet_json, client_tuple = wait_for_packet(socket_fd)
    if(len(packet_json['flags']) == 1 and packet_json['flags'][0]=="ACK"):
        print("Received ACK Packet")
        return packet_json

def wait_for_packet(socket_fd):
    packet_string, client_tuple = receive_message(socket_fd)
    packet_json = json.loads(packet_string)
    return (packet_json, client_tuple)

def send_SYN_ACK_Packet(socket_fd, client_tuple):
        res_packet = create_packet("", sequence=0, acknowledgement=1, flags=["SYN","ACK"])
        print("Sending SYN ACK")
        send_message(socket_fd, res_packet, client_tuple)
        return


def main():
    ip_port_tuple = argument_parser()
    TCP_handshake = False
    try:
        s = create_socket()
    except socket.error as e:
        exit(1)

    try:
        bind(s, ip_port_tuple)
    except socket.error:
        close_socket(s)
        exit(1)

    try:
        print("UDP Chat Server Started")
        while True:
            try:
                # Receive a message from the client
                if not TCP_handshake:
                    TCP_handshake = accept_connection(s)
                    
                if TCP_handshake:
                    data, client_address = receive_message(s)
                    print(f"Client ({client_address}): {data}")

            except KeyboardInterrupt:
                print("\nShutting down server")
                break
            except socket.error as e:
                print(f"Error during communication: {e}")
                break
    finally:
        close_socket(s)
        print("Server shut down")

if __name__ == "__main__":
    main()