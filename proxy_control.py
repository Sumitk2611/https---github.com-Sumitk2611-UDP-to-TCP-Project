import argparse
import socket
import json


def main():
    parser = argparse.ArgumentParser()

    def valid_percentage(value):
        percentage = float(value)
        if not 0 <= percentage <= 100:
            raise argparse.ArgumentTypeError(f"{value} must be between 0 and 100")
        return percentage

    def valid_delay_time(value):
        try:
            if '-' in str(value):
                start, end = map(int, value.split('-'))
                if start < 0 or end < 0:
                    raise argparse.ArgumentTypeError(f"Delay time cannot be negative")
                if start > end:
                    raise argparse.ArgumentTypeError(f"Range start must be less than end")
                return [start, end]
            else:
                delay = int(value)
                if delay < 0:
                    raise argparse.ArgumentTypeError(f"Delay time cannot be negative")
                return [delay, delay]
        except ValueError:
            raise argparse.ArgumentTypeError(f"Invalid delay time format. Use a number or range (e.g., '100-200')")

    parser.add_argument(
        "--client-drop",
        type=valid_percentage,
        help="Drop chance (0%% - 100%%) for client packets"
    )
    parser.add_argument(
        "--server-drop",
        type=valid_percentage,
        help="Drop chance (0%% - 100%%) for server packets"
    )
    parser.add_argument(
        "--client-delay",
        type=valid_percentage,
        help="Delay chance (0%% - 100%%) for client packets"
    )
    parser.add_argument(
        "--server-delay",
        type=valid_percentage,
        help="Delay chance (0%% - 100%%) for server packets"
    )
    parser.add_argument(
        "--client-delay-time",
        type=valid_delay_time,
        help="Delay time in ms (single value or range e.g., '100' or '100-200') for client packets"
    )
    parser.add_argument(
        "--server-delay-time",
        type=valid_delay_time,
        help="Delay time in ms (single value or range e.g., '100' or '100-200') for server packets"
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
