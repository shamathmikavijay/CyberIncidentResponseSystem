import os
from getpass import getpass
import mysql.connector

_password = None


def get_connection():
    global _password
    if _password is None:
        _password = os.getenv('MYSQL_PASSWORD')
        if _password is None:
            _password = getpass('MySQL password (input hidden): ')
    return mysql.connector.connect(
        host='localhost', user='root', password=_password,
        database='cyber_incident_db', connection_timeout=10
    )
