import argparse
import socket
import json


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--client-drop",
        type=float,
        help="Drop chance (0% - 100%) for client packets",
    )
    parser.add_argument(
        "--server-drop",
        type=float,
        help="Drop chance (0% - 100%) for server packets",
    )
    parser.add_argument(
        "--client-delay",
        type=float,
        help="Delay chance (0% - 100%) for client packets",
    )
    parser.add_argument(
        "--server-delay",
        type=float,
        help="Delay chance (0% - 100%) for server packets",
    )
    parser.add_argument(
        "--client-delay-time",
        type=int,
        help="Delay time in ms (fixed or range) for client packets",
    )
    parser.add_argument(
        "--server-delay-time",
        type=int,
        help="Delay time in ms (fixed or range) for server packets",
    )

    args = parser.parse_args()

    client_drop = args.client_drop
    server_drop = args.server_drop
    client_delay = args.client_delay
    server_delay = args.server_delay
    client_delay_time = args.client_delay_time
    server_delay_time = args.server_delay_time

    send_dict = {}
    if client_drop is not None:
        send_dict["client_drop"] = client_drop
    if server_drop is not None:
        send_dict["server_drop"] = server_drop
    if client_delay is not None:
        send_dict["client_delay"] = client_delay
    if server_delay is not None:
        send_dict["server_delay"] = server_delay
    if client_delay_time is not None:
        send_dict["client_delay_time"] = client_delay_time
    if server_delay_time is not None:
        send_dict["server_delay_time"] = server_delay_time

    msg = json.dumps(send_dict)

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect("/tmp/proxy_config.s")
    sock.sendall(msg.encode())

    return


if __name__ == "__main__":
    main()
