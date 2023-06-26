import socket
import threading
import logging.handlers
import re
import hashlib
import signal
import time

syslog_handler = logging.handlers.SysLogHandler(
    address=('192.168.1.13', 514))
logger = logging.getLogger()
logger.addHandler(syslog_handler)
logger.setLevel(logging.INFO)
control_abort = False


def log(message):
    print(f'CSR44-Proxy - {message}')
    logger.info(f'CSR44-Proxy - {message}')


def forward(source, destination, client):
    try:
        while True:
            data = source.recv(4096)
            if len(data) == 0:
                break
            destination.sendall(data)
    except Exception as e:
        pass
    finally:
        try:
            source.close()
        except:
            pass
        try:
            destination.close()
        except:
            pass


def handle_client(client_socket, client_address):
    try:
        # Receber requisição HTTP do cliente
        request = client_socket.recv(4096)

        # Armazenar a requisição em um bloco de bytes
        request_lines = request.split(b'\n')
        http_request_line = request_lines[0].decode()

        # Verificar se a palavra "monitorando" está no objeto requisitado
        if b"monitorando" in request:
            response_body = '''
                <html>
                    <head>
                        <meta charset="UTF-8">
                        <title>Exemplo de resposta HTTP </title>
                    </head>
                    <body>
                        <h3>Monitorando</h3>
                        <span><b>Acesso não autorizado! :(</b></span>
                    </body>
                </html>
            '''
            response_body = response_body.encode('utf-8')
            response = f'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {len(response_body)}\r\n\r\n'.encode('utf-8'
                                                                                                                            ) + response_body
            client_socket.sendall(response)

            # Log para o servidor SysLog
            log(f"Blocked request from {client_address} containing 'monitorando'")
        else:
            # Parse da requisição HTTP
            match = re.match(r'([A-Z]+) (\S+) HTTP/1.[01]', http_request_line)
            if match:
                method, url = match.groups()

                if method == 'CONNECT':
                    # Handle CONNECT method for HTTPS tunneling
                    destination_host = url.split(':')[0]
                    destination_port = int(url.split(':')[1])

                    # Establish a tunnel to the destination host
                    destination_socket = socket.socket(
                        socket.AF_INET, socket.SOCK_STREAM)
                    destination_socket.connect(
                        (destination_host, destination_port))

                    remote_ip, remote_port = destination_socket.getpeername()

                    # Log para o servidor SysLog
                    log(
                        f"New Client: {client_address}', Server: ('{remote_ip}', {remote_port}) - {destination_host}'")

                    # Inform the client that a tunnel has been established
                    client_socket.sendall(
                        b'HTTP/1.1 200 Connection Established\r\n\r\n')

                    # Forward bytes between client and destination
                    client_to_destination = threading.Thread(
                        target=forward, args=(client_socket, destination_socket, True))
                    destination_to_client = threading.Thread(
                        target=forward, args=(destination_socket, client_socket, False))
                    client_to_destination.start()
                    destination_to_client.start()
                    client_to_destination.join()
                    destination_to_client.join()
                else:
                    # Extrair o hostname do URL
                    url_split = url.split('/')
                    destination_host = url_split[2]

                    port = 80  # url_split[1]

                    # Encaminhar requisição para o servidor
                    destination_socket = socket.socket(
                        socket.AF_INET, socket.SOCK_STREAM)
                    destination_socket.connect((destination_host, int(port)))

                    remote_ip, remote_port = destination_socket.getpeername()

                    # Log para o servidor SysLog
                    log(
                        f"New Client: {client_address}', Server: ('{remote_ip}', {remote_port}) - {destination_host}'")

                    destination_socket.sendall(request)

                    # Receber resposta do servidor
                    response = destination_socket.recv(8196)

                    # Repassar resposta para o cliente
                    client_socket.send(response)

                    # Encerrar a conexão com o servidor
                    destination_socket.close()

                    # Log para o servidor SysLog
                    status_code = response.split()[1].decode()
                    log(
                        f"New Response: Client: {client_address}, Server: {destination_host}, Status Code: {status_code}")
            else:
                client_socket.send(b'HTTP/1.1 400 Bad Request\r\n\r\n')
    except Exception as e:
        log(f"Exception handling request: {e}")
    finally:
        # Encerrar a conexão com o cliente
        client_socket.close()


def integrity_check():
    global control_abort
    log("Performing integrity check...")
    with open('integrity_check.txt', 'r') as f:
        integrity_check = f.read()
        sum = ''
        with open('main.py', 'rb') as actual_f:
            contents = actual_f.read()
            sum = hashlib.sha256(contents).hexdigest()

        log(f"Original File: {integrity_check}")
        log(f"Actual File: {sum}")

        if integrity_check == sum:
            log("Integrity check passed!")
        else:
            log("Integrity check failed! Aborting...")
            control_abort = True
            exit()


def main_loop():
    log("Initializing the CSR44-Proxy...")
    integrity_check()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('127.0.0.1', 8080))
    server.listen(5)

    log("Proxy server listening on port 8080...")

    try:
        while True:
            # Aceitar conexão do browser
            client_socket, client_address = server.accept()

            # Criar uma thread para lidar com a conexão do browser
            client_handler = threading.Thread(
                target=handle_client, args=(client_socket, client_address), daemon=True)
            client_handler.start()
    except KeyboardInterrupt as e:
        server.close()


def signal_handler(signum, frame):
    res = input("Ctrl-c was pressed. Do you really want to exit? y/n ")
    if res == 'y':
        exit(1)


signal.signal(signal.SIGINT, signal_handler)

main_thread = threading.Thread(
    target=main_loop, daemon=True)

main_thread.start()

while (True):
    if control_abort:
        exit()
    time.sleep(1)
