import os
import sys

import argparse

from DBAgent import Users, Server
from DBAgent.orm import Services
from config import db

parser = argparse.ArgumentParser(description="This program will create a server in the Database, and print the new server id (if possible)")
parser.add_argument("-uid", "--user-id", required=True, type=int, metavar="user_id", help="The user id own the server.")
parser.add_argument("-ip", "--server-ip", required=True, metavar="server_ip",
                    help="The server ip that will use for redirect the requests.")
parser.add_argument("-ip", "--server-ip", required=True, metavar="server_ip",
                    help="The server ip that will use for redirect the requests.")
parser.add_argument("-dns", "--server-dns", required=True, metavar="server_dns",
                    help="The server dns that will use for the requests.")

def run():
    args = parser.parse_args()
    server = Server(
        user_id=args.user_id,
        server_ip=args.server_ip,
        server_dns=args.server_dns,
        active=True
    )
    db.insert(server)
    services = Services(
        server_id=server.item_id,
        user_id=args.user_id,
    )
    db.insert(services)
    print("Done")
    print("The new server id is: ", server.item_id)


if __name__ == '__main__':
    run()
