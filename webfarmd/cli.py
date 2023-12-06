import argparse
import socket


def send_request(request):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(("localhost", 9342))
    client.send(request.encode("utf-8"))
    response = client.recv(1024).decode("utf-8")
    print(f"{response}")
    client.close()


def run_admin_client():
    argparser = argparse.ArgumentParser()
    argparser.add_argument("request", choices=["status"])
    args = argparser.parse_args()
    send_request(args.request)
