import socket
import argparse

def argument_parser():
    """Parse command-line arguments for IP and port."""
    port = 5000
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--port", type=int, help="port to connect to")
    parser.add_argument("-ip", "--ip_address", required=True, help="the server's IP address")
    args = parser.parse_args()

    if args.port:
        port = args.port
        print(f"Using Port: {port}")
    else:
        print(f"No port provided. Using default port: {port}")

    if args.ip_address:
        ip_address = args.ip_address
        print(f"Inputted IP Address: {ip_address}")
    else:
        print("No IP address provided")
        exit(0)

    return ip_address, port

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

def main():
    ip_port_tuple = argument_parser()

    try:
        s = create_socket()
    except socket.error:
        exit(1)

    try:
        print("UDP Client Started. Type your messages below:")
        while True:
            try:
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
