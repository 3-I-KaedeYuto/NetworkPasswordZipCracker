import socket
import struct
import pickle
import threading
import time
import sys
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

## グローバル変数

# ログ確認用ファイル(log.txt)
logfile = open("log.txt", mode="w")

# ホスト名またはホストアドレス(ループバックならlocalhost、LAN, WANを経由するならプライベートipアドレスを指定)
HOST = "192.168.0.1"
# サーバーポート
PORT = 32767

# 解析用クライアントの数[default=3]
ANALYZER_COUNT = 3
# 解析対象ファイルのパス[default="file.zip"]
file_path = "file.zip"

# パスワードの長さ[default=4]
password_length = 4
# 数字を含むかどうか[default=False]
has_integers = False
# アルファベット小文字を含むかどうか[default=True]
has_lower_alphabets = True
# アルファベット小文字を含むかどうか[default=False]
has_upper_alphabets = False
# 記号を含むかどうか[default=False]
has_symbols = False

## 総当たりパスワード生成用クラス
class BruteForce:
    # コンストラクタ
    def __init__(self, length:int, has_integer:bool, has_lower_alphabet:bool, has_upper_alphabet:bool, has_symbol:bool) -> None:
        self.length = length
        self.has_integer = has_integer
        self.has_lower_alphabet = has_lower_alphabet
        self.has_upper_alphabet = has_upper_alphabet
        self.has_symbol = has_symbol
        self.characters = []
        if self.has_integer: self.__addIntegers()
        if self.has_lower_alphabet: self.__addLowerAlphabets()
        if self.has_upper_alphabet: self.__addUpperAlphabets()
        if self.has_symbol: self.__addSymbols()
        self.indexes = [0] * length
        self.indexes[0] = -1

    def __addIntegers(self) -> None:
        self.__add(48, 10)
        
    def __addLowerAlphabets(self) -> None:
        self.__add(97, 26)
        
    def __addUpperAlphabets(self) -> None:
        self.__add(65, 26)
        
    def __addSymbols(self) -> None:
        symbol_list = [
            '!','"', '#', '$', '%', '&', '\'', '(', ')', '=', '+', '-', '*', '/', '\\', '?', '.', ',',
            '<', '>', '_', '@', '`', '{', '}', '[', ']', ':', ';', '^', '~', '|'
        ]
        for c in symbol_list:
            self.characters.append(c)
            
    def __add(self, first:int, length:int) -> None:
        for i in range(length):
            self.characters.append(chr(first + i))

    # パスワード生成関数
    def next(self) -> str:
        self.indexes[0] += 1
        for i in range(self.length - 1):
            if self.indexes[i] >= len(self.characters):
                self.indexes[i] = 0
                self.indexes[i + 1] += 1
        if self.indexes[self.length - 1] >= len(self.characters):
            return None
        result = ''
        for i in range(self.length):
            result += self.characters[self.indexes[self.length - i - 1]]
        self.now_password = result
        return self.now_password

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

# 全クライアント送信用関数
def send_all(sockets:list, obj) -> None:
    for sock in sockets:
        send_packet(sock, obj)

# ログ追記関数
def log(msg:str) -> None:
    now = time.strftime("%H:%M:%S")
    logfile.write("[{}] [Thread: {}]: {}\n".format(now, threading.get_ident(), msg))
    print("[{}] [Thread: {}]: {}".format(now, threading.get_ident(), msg))

# パスワード割り当て用関数
def analyze(socket:socket.socket) -> None:
    global password
    while password != None:
        res = read_packet(socket)
        if res.obj["event"] == "request_password":
            amount = res.obj["max_amount"]
            send_passwords = []
            for i in range(amount):
                send_passwords.append(password)
                password = attacker.next()
                if password == None:
                    break
            send_data = {
                "event" : "send_password",
                "passwords" : send_passwords
            }
            log("Sending {}".format(send_data))
            send_packet(socket, send_data)
        elif res.obj["event"] == "found_password":
            log("Password found [{}]".format(res.obj["password"]))
            finish()
    log("Could not find the password")
    finish()

# 通信切断用関数
def close() -> None:
    for client in analyzers:
        client.close()

# 終了関数
def finish() -> None:
    end_time = time.perf_counter()
    log("Analyze finished at {} seconds".format(end_time - start_time))
    send_data = {
        "event": "crack_finished"
    }
    send_all(analyzers, send_data)
    close()
    logfile.close()
    sys.exit(0)


## メイン処理
# ソケットの作成、接続待ち
sc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sc.bind((HOST, PORT))
sc.listen(5)
log("Waiting connection on {}:{}".format(HOST,PORT))

analyzers = []


# 初期設定
while True:
    clientsocket, address = sc.accept()
    log(f"Connection from {address} has been established!")
    send_data = {
        "event" : "connection_success"
    }
    send_packet(clientsocket, send_data)
    res = read_packet(clientsocket)
    log(res.obj)
    if res.obj["event"] == "connect" and res.obj["type"] == "analyzer":
        analyzers.append(clientsocket)

    if len(analyzers) == ANALYZER_COUNT:
        break

log("Analyzers ready")

#ファイル送信
with open(file_path, mode="rb") as f:
    file_data = f.read()

send_data = {
    "event": "send_file",
    "file": file_data
}
send_all(analyzers, send_data)

#パスワード全生成
attacker = BruteForce(password_length, has_integers, has_lower_alphabets, has_upper_alphabets, has_symbols)
password = attacker.next()

start_time = time.perf_counter()

# パスワード割り当て
with ThreadPoolExecutor(max_workers=ANALYZER_COUNT) as tpe:
    for s in analyzers:
        tpe.submit(analyze, s)

