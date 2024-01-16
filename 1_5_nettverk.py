#!/usr/bin/env python3

import socket
import struct
import select

TCP_IP = "127.0.0.1"
TCP_PORT = 10015

def main():
    mainconn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    mainconn.connect((TCP_IP, TCP_PORT))

    conns = [mainconn]
    for _ in range(10):
        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn.connect((TCP_IP, TCP_PORT))

        conns.append(conn)

    cnt = 0
    sm = 0
    s = ""
    while True:
        read_sock, _, _ = select.select(conns, [], [])

        for rs in read_sock:
            data = rs.recv(2048)
            if rs == mainconn:
                print(data.decode("utf-8"))
            elif cnt < 10:
                num = struct.unpack(">i", data)
                sm += num[0]
                cnt += 1
                if cnt == 10:
                    mainconn.send(struct.pack(">i", sm))
            else:
                s += data.decode("utf-8")
                if s[-1] == "\n":
                    print(s)
                    cnt += 1
                    if cnt > 100:
                        exit()




if __name__ == "__main__":
    main()


