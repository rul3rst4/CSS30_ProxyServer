import socket
import threading
import logging.handlers
import re

# syslog_handler = logging.handlers.SysLogHandler(
#     address=('endereço_do_syslog', 514))
# logger = logging.getLogger()
# logger.addHandler(syslog_handler)
# logger.setLevel(logging.INFO)


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
            response = b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><body><h1>Acesso n\xc3\xa3o autorizado!</h1></body></html>'
            client_socket.sendall(response)

            # Log para o servidor SysLog
            # logger.info(
            #     f"Blocked request from {client_address} containing 'monitorando'")
        else:
            # Parse da requisição HTTP
            match = re.match(r'([A-Z]+) (\S+) HTTP/1.[01]', http_request_line)
            if match:
                method, url = match.groups()
                print(url)

                if method == 'CONNECT':
                    # Handle CONNECT method for HTTPS tunneling
                    destination_host = url.split(':')[0]
                    destination_port = int(url.split(':')[1])

                    # Establish a tunnel to the destination host
                    destination_socket = socket.socket(
                        socket.AF_INET, socket.SOCK_STREAM)
                    destination_socket.connect(
                        (destination_host, destination_port))

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
                    destination_socket.sendall(request)

                    # Receber resposta do servidor
                    response = destination_socket.recv(4096)

                    # Repassar resposta para o cliente
                    client_socket.send(response)

                    # Encerrar a conexão com o servidor
                    destination_socket.close()

                    # Log para o servidor SysLog
                    status_code = response.split()[1].decode()
                    # logger.info(
                    #     f"Client: {client_address}, Server: {destination_host}, Status Code: {status_code}")
            else:
                client_socket.send(b'HTTP/1.1 400 Bad Request\r\n\r\n')
    except Exception as e:
        print(f"Exception handling request: {e}")
    finally:
        # Encerrar a conexão com o cliente
        client_socket.close()


# Configurar o servidor proxy
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(('127.0.0.1', 8080))
server.listen(5)

print("Proxy server listening on port 8080...")

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
