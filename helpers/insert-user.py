import os
import sys

import argparse

from DBAgent import Users
from config import db

parser = argparse.ArgumentParser(description="This program will create a user in the Database, and print the new user id (if possible)")
parser.add_argument("-un", "--user-name", required=True,metavar="user_name", help="The user name that will use for login to the system")
parser.add_argument("-pwd", "--password", required=False, default="123456", metavar="password",
                    help="The password that will use for login to the system")

def run():
    args = parser.parse_args()
    username = args.user_name
    user = Users(
        email="eliran@eliran.com",
        password="123456",
        active=True,
        is_admin=True
    )
    db.insert(user)
    print("The new user id is: ", user.item_id)


if __name__ == '__main__':
    run()
