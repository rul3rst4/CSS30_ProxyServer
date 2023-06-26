import socket
import threading
import logging.handlers
import re
import hashlib
import signal
import time


class CSR44Proxy:

    def __init__(self, syslog_address=('192.168.1.13', 514)):
        self.abort = False
        self.logger = logging.getLogger()
        syslog_handler = logging.handlers.SysLogHandler(address=syslog_address)
        self.logger.addHandler(syslog_handler)
        self.logger.setLevel(logging.INFO)

    def log(self, message):
        log_text = f'CSR44-Proxy - {message}'
        print(log_text)
        self.logger.info(log_text)

    def relay_data(self, source, destination):
        try:
            while True:
                data = source.recv(4096)
                if not data:
                    break
                destination.sendall(data)
        except:
            pass
        finally:
            for s in [source, destination]:
                try:
                    s.close()
                except:
                    pass

    def process_client(self, client_socket, client_address):
        try:
            request = client_socket.recv(4096)
            request_lines = request.split(b'\n')
            http_request_line = request_lines[0].decode()

            if b"monitorando" in request:
                html_body = '''
                    <html>
                        <head>
                            <meta charset="UTF-8">
                            <title>HTTP Response Example</title>
                        </head>
                        <body>
                            <h3>Monitoring</h3>
                            <span><strong>Unauthorized Access! :(</strong></span>
                        </body>
                    </html>
                '''
                html_body_encoded = html_body.encode('utf-8')
                response = f'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {len(html_body_encoded)}\r\n\r\n'.encode(
                    'utf-8') + html_body_encoded
                client_socket.sendall(response)
                self.log(
                    f"Blocked request from {client_address} containing 'monitorando'")
            else:
                match = re.match(
                    r'([A-Z]+) (\S+) HTTP/1.[01]', http_request_line)
                if match:
                    method, url = match.groups()

                    if method == 'CONNECT':
                        destination_host, destination_port = url.split(':')
                        destination_socket = socket.socket(
                            socket.AF_INET, socket.SOCK_STREAM)
                        destination_socket.connect(
                            (destination_host, int(destination_port)))
                        r_ip, r_port = destination_socket.getpeername()

                        self.log(
                            f"New Client: {client_address}', Server: ('{r_ip}', {r_port}) - {destination_host}'")

                        client_socket.sendall(
                            b'HTTP/1.1 200 Connection Established\r\n\r\n')

                        threading.Thread(target=self.relay_data, args=(
                            client_socket, destination_socket)).start()
                        threading.Thread(target=self.relay_data, args=(
                            destination_socket, client_socket)).start()

        except Exception as ex:
            self.log(f"Exception handling request: {ex}")
        finally:
            client_socket.close()

    def integrity_check(self):
        self.log("Verifying integrity...")
        try:
            with open('integrity_check.txt') as orig_f:
                orig_hash = orig_f.read().strip()
                print(orig_hash)
                with open('main.py', 'rb') as curr_f:
                    curr_hash = hashlib.sha256(curr_f.read()).hexdigest()
                    print(curr_hash)
                if orig_hash == curr_hash:
                    self.log("Integrity check successful!")
                else:
                    self.log("Integrity check failed! Exiting...")
                    self.abort = True
                    exit()
        except:
            self.log("Error during integrity check.")

    def run(self):
        self.log("Initializing the CSR44-Proxy...")
        self.integrity_check()

        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind(('127.0.0.1', 8080))
        server_socket.listen(5)
        self.log("Proxy server listening on port 8080...")

        try:
            while True:
                client_socket, client_address = server_socket.accept()
                threading.Thread(target=self.process_client, args=(
                    client_socket, client_address), daemon=True).start()
        except KeyboardInterrupt:
            server_socket.close()


def on_keyboard_interrupt(signal, frame):
    user_input = input("Ctrl-C pressed. Exit? y/n ")
    if user_input == 'y':
        exit(1)


if __name__ == "__main__":
    signal.signal(signal.SIGINT, on_keyboard_interrupt)
    proxy = CSR44Proxy()
    proxy.run()
