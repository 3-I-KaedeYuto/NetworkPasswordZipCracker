import socket
import struct
import pickle
import threading
import time
import sys
import os
import shutil
from types import SimpleNamespace
from zipfile import ZipFile
from concurrent.futures import ProcessPoolExecutor

## グローバル変数
def set_variable():
    global logfile, HOST, PORT, MAX_PASSWORDS, MAX_THREADS, WORKING_DIRECTRY, ZIP_FILE
    # ログ確認用ファイル(log.txt)
    logfile = open("log.txt", mode="w")

    # 接続先ipアドレス
    HOST = "192.168.0.1"
    # 接続先ポート [default: 32767]
    PORT = 32767

    # 一度に受け取るパスワードの個数の最大値[default=10]
    MAX_PASSWORDS = 50
    # 同時に動作するスレッド数[default=3]
    MAX_THREADS = 10

    # 作業ディレクトリ[default="files/"]
    WORKING_DIRECTRY = "files/"
    # 解析対象ファイル[default="file.zip"]
    ZIP_FILE = "file.zip"


## 通信用関数
def _read_length(stream:socket.socket) -> int:
    assert struct.calcsize(">I") == 4
    return struct.unpack(">I", stream.recv(4))[0]

def _read_payload(stream:socket.socket, length:int) -> bytes:
    return stream.recv(length)

# 受信関数
def read_packet(stream:socket.socket) -> SimpleNamespace:
    length = _read_length(stream)
    payload = _read_payload(stream, length)
    obj = pickle.loads(payload)
    return SimpleNamespace(**locals())

# 送信関数
def send_packet(sock:socket.socket, obj) -> None:
    payload = pickle.dumps(obj)
    length = len(payload)
    sock.sendall(struct.pack(">I", length))
    sock.sendall(payload)

# 作業ディレクトリ初期化関数
def refresh_directry() -> None:
    if(os.path.isdir(WORKING_DIRECTRY)):
        shutil.rmtree(WORKING_DIRECTRY)
    os.mkdir(WORKING_DIRECTRY)


# ログ追記関数
def log(msg:str) -> None:
    now = time.strftime("%H:%M:%S")
    logfile.write("[{}] [Thread: {}]: {}\n".format(now, threading.get_ident(), msg))
    print("[{}] [Thread: {}]: {}".format(now, threading.get_ident(), msg))

# 解析用関数
def extract(pwd:str) -> None:
    print("called")
    try:
        print("Extracting with password [{}]".format(pwd))
        zf.extractall(path=WORKING_DIRECTRY, pwd=pwd.encode("utf-8"))
        send_data = {
            "event": "found_password",
            "password": pwd
        }
        send_packet(sc, send_data)
        print("The password found")
        global found_password
        found_password = True
    except:
        pass


# 終了関数
def finish() -> None:
    sc.close()
    logfile.close()
    sys.exit(0)

## メイン処理
# ソケットの作成、接続
def main():
    global sc, zf
    log("Starting Connection")
    sc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sc.connect((HOST, PORT))
    sc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)


    # 初期設定
    res = read_packet(sc)
    if res.obj["event"] == "connection_success":
        log("Connection success")
    else:
        log("Connection failed")
        sys.exit(0)

    send_data = {
        "event": "connect",
        "type": "analyzer"
    }
    send_packet(sc, send_data)

    refresh_directry()
    FILE_PATH = WORKING_DIRECTRY + ZIP_FILE

    # ファイル受信
    res = read_packet(sc)
    if res.obj["event"] == "send_file":
        with open(FILE_PATH, mode="wb") as f:
            f.write(res.obj["file"])

    global found_password
    found_password = False

    # 解析

    zf = ZipFile(FILE_PATH)


    with ProcessPoolExecutor(max_workers=MAX_THREADS) as ppe:
        while True:
            try:
                send_data = {
                    "event":"request_password",
                    "max_amount" : MAX_PASSWORDS
                }
                send_packet(sc, send_data)
                res = read_packet(sc)
                if res.obj["event"] == "send_password":
                    f = None
                    for pw in res.obj["passwords"]:
                        f = ppe.submit(extract, pw)
                    while not f.done:
                        continue
                elif res.obj["event"] == "crack_finished":
                    log("The password was found by other client")
                    finish()
            except ConnectionAbortedError:
                log("Lost connection")
                finish()
            except ConnectionResetError:
                log("Lost connection")
                finish()   

if __name__ == "__main__":
    set_variable()
    main()
