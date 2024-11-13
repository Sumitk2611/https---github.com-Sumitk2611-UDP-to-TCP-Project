import socket
import argparse

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

def main():
    ip_port_tuple, timeout = argument_parser()

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
