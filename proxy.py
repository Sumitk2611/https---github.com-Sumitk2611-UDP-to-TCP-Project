import socket
from result import Ok, Err, Result, is_ok, is_err
import argparse
from dataclasses import dataclass
import threading
import os
import time
import json
import random
import select


@dataclass
class ProxyConfig:
    listen_ip: str
    listen_port: int
    target_ip: str
    target_port: int
    client_drop: int
    server_drop: int
    client_delay: int
    server_delay: int
    client_delay_time: int
    server_delay_time: int


class ArgumentsHandler:
    def __init__(self):
        self._parser = argparse.ArgumentParser()
        self._setup_parser()

    def parse(self) -> Result[None, str]:
        try:
            args = self._parser.parse_args()
        except:
            return Err("An error occured while parsing the arguments")

        listen_ip = args.listen_ip
        listen_port = args.listen_port
        target_ip = args.target_ip
        target_port = args.target_port

        client_drop = args.client_drop
        server_drop = args.server_drop
        client_delay = args.client_delay
        server_delay = args.server_delay
        client_delay_time = args.client_delay_time
        server_delay_time = args.server_delay_time

        self.proxy_config = ProxyConfig(
            listen_ip,
            listen_port,
            target_ip,
            target_port,
            client_drop,
            server_drop,
            client_delay,
            server_delay,
            client_delay_time,
            server_delay_time,
        )

        return Ok(None)

    def _parse_and_set_live_values_from_json(self, obj: str):
        parsed: dict = json.loads(obj)

        client_drop = parsed.get("client_drop")
        server_drop = parsed.get("server_drop")
        client_delay = parsed.get("client_delay")
        server_delay = parsed.get("server_delay")
        client_delay_time = parsed.get("client_delay_time")
        server_delay_time = parsed.get("server_delay_time")

        print("before", self.proxy_config)
        print()

        print("changes", parsed)
        print()

        if client_drop is not None:
            self.proxy_config.client_drop = client_drop
        if server_drop is not None:
            self.proxy_config.server_drop = server_drop
        if client_delay is not None:
            self.proxy_config.client_delay = client_delay
        if server_delay is not None:
            self.proxy_config.server_delay = server_delay
        if client_delay_time is not None:
            self.proxy_config.client_delay_time = client_delay_time
        if server_delay_time is not None:
            self.proxy_config.server_delay_time = server_delay_time

        print("after", self.proxy_config)
        print()

    def _live_listener(self, on_update):
        if os.path.exists("/tmp/proxy_config.s"):
            os.remove("/tmp/proxy_config.s")

        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind("/tmp/proxy_config.s")

        while True:
            server.listen(1)
            conn, addr = server.accept()
            datagram = conn.recv(1024)

            if datagram:
                self._parse_and_set_live_values_from_json(datagram.decode())
                on_update(self.proxy_config)

            conn.close()

    def start_listener(self, on_update) -> Result[None, str]:
        try:
            threading.Thread(target=self._live_listener, args=[on_update]).start()
        except:
            return Err(
                "Something went wrong while trying to start the config listener thread."
            )

        return Ok(None)

    def _setup_parser(self) -> None:
        self._parser.add_argument(
            "--listen-ip", required=True, help="IP to bind the proxy server"
        )
        self._parser.add_argument(
            "--listen-port",
            required=True,
            type=int,
            help="Port to listen for client packets",
        )
        self._parser.add_argument(
            "--target-ip", required=True, help="IP of the server to forward packets to"
        )
        self._parser.add_argument(
            "--target-port", required=True, type=int, help="Port of the server"
        )
        self._parser.add_argument(
            "--client-drop",
            type=float,
            default=0,
            help="Drop chance (0% - 100%) for client packets",
        )
        self._parser.add_argument(
            "--server-drop",
            type=float,
            default=0,
            help="Drop chance (0% - 100%) for server packets",
        )
        self._parser.add_argument(
            "--client-delay",
            type=float,
            default=0,
            help="Delay chance (0% - 100%) for client packets",
        )
        self._parser.add_argument(
            "--server-delay",
            type=float,
            default=0,
            help="Delay chance (0% - 100%) for server packets",
        )
        self._parser.add_argument(
            "--client-delay-time",
            type=int,
            default=0,
            help="Delay time in ms (fixed or range) for client packets",
        )
        self._parser.add_argument(
            "--server-delay-time",
            type=int,
            default=0,
            help="Delay time in ms (fixed or range) for server packets",
        )


class ProxyServer:
    def __init__(self, args: ProxyConfig) -> None:
        self.args = args
        self.client_to_server_sockets_map = {}
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def update_args(self, args: ProxyConfig):
        self.args = args

    def __should_drop_client_packet(self) -> bool:
        chance = self.args.client_drop / 100.0
        rand = random.random()
        return rand < chance

    def __should_delay_client_packet(self) -> bool:
        return random.random() < (self.args.client_delay / 100.0)

    def __should_drop_server_packet(self) -> bool:
        chance = self.args.server_drop / 100.0
        rand = random.random()
        return rand < chance

    def __should_delay_server_packet(self) -> bool:
        return random.random() < (self.args.server_delay / 100.0)

    def __ms_to_s(self, raw: int):
        return raw / 1000.0

    def __is_server(self, ip, port):
        return ip == self.args.target_ip and port == self.args.target_port

    def __send_to_server(
        self, ip: str, port: int, data, sock: socket.socket
    ) -> Result[socket, str]:
        try:
            if sock is None:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(data, (ip, port))
            return Ok(sock)
        except socket.error as e:
            return Err(e.strerror)

    def __send_to_client( self, ip: str, port: int, data) -> Result[None, str]:
        try:
            self.sock.sendto(data, (ip, port))
            return Ok(None)
        except socket.error as e:
            return Err(e.strerror)

    def __handle_server_connection(self, client_ip, client_port, data):
        print("Server connection!")

        if self.__should_drop_server_packet():
            print("Dropping server packet to client", client_ip, client_port)
            return

        if self.__should_delay_server_packet():
            delay = self.__ms_to_s(self.args.server_delay)
            time.sleep(delay)

        send_result = self.__send_to_client(
            client_ip, client_port, data 
        )
        if is_err(send_result):
            print(
                f"An error occured while sending packet from server to {client_ip} {client_port} client"
            )

    def __handle_client_connection(self, client_ip, client_port, data, server_socket):
        if self.__should_drop_client_packet():
            print("Dropping client packet from client", client_ip, client_port)
            return

        if self.__should_delay_client_packet():
            delay = self.__ms_to_s(self.args.client_delay)
            time.sleep(delay)

        server_ip = self.args.target_ip
        server_port = self.args.target_port

        send_result = self.__send_to_server(
            server_ip, server_port, data, sock=server_socket
        )
        if is_err(send_result):
            print(
                f"An error occured while sending packet from client {client_ip} {client_port} to server"
            )

        sock = send_result.ok_value
        if server_socket is None:
            self.client_to_server_sockets_map[(client_ip, client_port)] = sock

    def start(self):
        listen_ip = self.args.listen_ip
        listen_port = self.args.listen_port

        self.sock.bind((listen_ip, listen_port))

        while True:
            rrrlist = [self.sock] + [x for x in self.client_to_server_sockets_map.values()]
            rlist, _, _ = select.select(
                rrrlist,
                [],
                [],
            )

            for sock in rlist:
                if sock is self.sock:
                    data, addr = sock.recvfrom(1024)
                    client_ip, client_port = addr

                    print(f"Received packet: {data} from {client_ip} {client_port}")

                    if (client_ip, client_port) in self.client_to_server_sockets_map:
                        sock = self.client_to_server_sockets_map.get(
                            (client_ip, client_port)
                        )
                        self.__handle_client_connection(
                            client_ip, client_port, data, sock
                        )
                    else:
                        self.__handle_client_connection(
                            client_ip, client_port, data, None
                        )
                else:
                    data, addr = sock.recvfrom(1024)
                    (client_ip, client_port) = next((key for key, val in self.client_to_server_sockets_map.items() if val == sock), None)

                    self.__handle_server_connection(client_ip, client_port, data)



def main():
    arg_handler = ArgumentsHandler()

    parse_result = arg_handler.parse()
    if is_err(parse_result):
        print(parse_result.err())
        exit()

    proxy_server = ProxyServer(arg_handler.proxy_config)

    listener_result = arg_handler.start_listener(
        lambda new_config: proxy_server.update_args(new_config)
    )
    if is_err(listener_result):
        print(listener_result.err())
        exit()

    proxy_server.start()

    return


if __name__ == "__main__":
    main()
