import socket
import argparse

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

def send_message(socket_fd, message, client_address):
    try:
        socket_fd.sendto(message.encode('utf-8'), client_address)
    except socket.error as e:
        print(f"Error sending message: {e}")
        raise e

def receive_message(socket_fd):
    try:
        data, client_address = socket_fd.recvfrom(1024)  # Receive up to 1024 bytes
        return data.decode('utf-8'), client_address
    except socket.error as e:
        print(f"Error receiving message: {e}")
        raise e
    
def main():
    ip_port_tuple = argument_parser()

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