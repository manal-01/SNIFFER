from datetime import datetime
from scapy.all import *

import pyodbc



def connect_db(driver_name, server_name):
    try:
        conn = pyodbc.connect(f'Driver={driver_name};'
                              f'Server={server_name};'
                              'Database=Master;'
                              'Trusted_Connection=yes;')
        print("Connected to the database successfully")
        conn.autocommit = True
        return conn
    except:
        print('Connection failed to SQL Server')


def use_table(conn):
    try:
        cursor = conn.cursor()
        cursor.execute('CREATE DATABASE Packets')
        conn.commit()
        cursor.execute("USE Packets")
    except:
        cursor.execute("USE Packets")
    try:
        cursor.execute('''
                 CREATE TABLE PacketCapture (
                        PacketUID NVARCHAR(80) PRIMARY KEY,
                        Time VARCHAR(30),
                        Source VARCHAR(30),
                        Destination  VARCHAR(30),
                        PortName VARCHAR(10),
                        Info TEXT,
                        Show TEXT,
                        Hexdump TEXT
                        ); '''
                       )
        print('Table created successfully')
        return cursor
    except:
        cursor = conn.cursor()
        cursor.execute("USE Packets")
        return cursor

def is_ipv4_address(s):
    p = s.split('.')
    return len(p) == 4 and all(n.isdigit() and 0 <= int(n) < 256 for n in p)