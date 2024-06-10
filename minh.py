import socket
import json
import threading
from random import randint
from hashlib import sha256

INF_POINT = None

# Helper functions 
def reduce_mod(x:int, p:int) -> int:
    return x % p

def equal_mod(x:int, y:int, p:int) -> bool:
    return reduce_mod(x - y, p) == 0

def inverse_mod(x:int, p:int) -> int:
    if reduce_mod(x, p) == 0:
        return None
    return pow(x, p-2, p)

class File:
    @classmethod
    def read(cls, path:str) -> str:
        with open(path, "r") as file:
            return file.read()

    @classmethod
    def write(cls, path:str, message:str) -> None:
        with open(path, "w") as file:
            file.write(message)

    @classmethod
    def append(cls, path:str, message:str) -> None:
        with open(path, "a") as file:
            file.write(message)

    @classmethod
    def get_size(cls, path:str) -> int:
        pass

class Converter:
    @classmethod
    def hex_to_string(cls, h:hex) -> str:
        pass

    @classmethod
    def string_to_hex(cls, s:str) -> hex:
        pass

class Point:
    def __init__(self, x:int, y:int) -> None:
        self.x = x
        self.y = y
    
    def __str__(self) -> str:
        return f"({self.x}, {self.y})"

class Curve:
    def __init__(self, name:str, a:int, b:int, p:int, g:Point, n:int) -> None:
        self.name = name
        self.a = a
        self.b = b
        self.p = p
        self.g = g
        self.n = n

    def add(self, p1:Point, p2:Point) -> Point:
        if p1 == INF_POINT:
            return p2
        if p2 == INF_POINT:
            return p1

        x1, y1 = p1.x, p1.y
        x2, y2 = p2.x, p2.y

        if equal_mod(x2, x1, self.p) and equal_mod(y2, -y1, self.p):
            return INF_POINT

        if equal_mod(x1, x2, self.p) and equal_mod(y1, y2, self.p):
            u = reduce_mod((3*(x1**2) + self.a), self.p) * inverse_mod((2 * y1), self.p)
        else:
            u = reduce_mod((y2 - y1), self.p) * inverse_mod((x2 - x1), self.p)

        v  = reduce_mod((y1 - u * x1), self.p)
        x3 = reduce_mod((u**2 - x1 - x2), self.p)
        y3 = reduce_mod((-u * x3 - v), self.p) 

        return Point(x3, y3)

    def scalar_multiplication(self, k:int, p:Point) -> Point:
        q = INF_POINT
        while k != 0:
            if k & 1 != 0:
                q = self.add(q, p)
            p = self.add(p, p)
            k >>= 1
        return q
    
    def contain(self, p:Point) -> bool:
        return equal_mod(p.y**2, p.x**3 + self.a * p.x + self.b, self.p)

secp256k1 = Curve(
    name="secp256k1",
    a=0x0000000000000000000000000000000000000000000000000000000000000000,
    b=0x0000000000000000000000000000000000000000000000000000000000000007,
    p=0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f,
    g=Point(
        0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
        0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
    ),
    n=0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
)

class PublicKey:
    def __init__(self, p:Point, curve:Curve) -> None:
        self.p = p
        self.curve = curve

    def to_string(self, encoded=False) -> str:
        base = 2 * (1 + len("%x" % self.curve.n))

        x = str(hex(self.p.x)).zfill(base)
        y = str(hex(self.p.y)).zfill(base)

        if encoded:
            return "0004" + x + y
        return x + y 

    def from_string(self) -> str:
        pass

    def to_der(self) -> str:
        pass

    def from_der(self) -> str:
        pass

    def __str__(self) -> str:
        return f"curve: {self.curve.name}\npoint: {self.p}"

class PrivateKey:
    def __init__(self, curve=secp256k1, secret=None):
        self.curve = curve
        self.secret = secret or randint(1, curve.n-1)

    def generate_public_key(self):
        public_key_point = self.curve.scalar_multiplication(self.secret, self.curve.g)
        public_key = PublicKey(public_key_point, self.curve)
        return public_key

    def load_from_pem_file(self, path:str):
        pem_file_data = File.read(path)
        pem = None # base64.decode(pem_file.split("\n")[0])

    def to_string(self) -> str:
        pass

    def to_pem(self) -> str:
        pass

    def __str__(self):
        return f"curve:  {self.curve.name}\nsecret: {hex(self.secret)}"

class Signature:
    def __init__(self, r:int, s:int, r_id:int):
        self.r = r
        self.s = s
        self.r_id = r_id

    def __str__(self) -> str:
        return f"r: {self.r} \ns: {self.s}\nr_id: {self.r_id}"

def sign(private_key:PrivateKey, message:bytes) -> Signature:
    curve  = private_key.curve
    secret = private_key.secret

    e = int(sha256(message).hexdigest(), 16)
    r, s = 0, 0
    while r == 0 or s == 0:
        k  = randint(1, curve.n-1)
        kp = curve.scalar_multiplication(k, curve.g)
        
        r  = reduce_mod(kp.x, curve.n)
        s  = reduce_mod(inverse_mod(k, curve.n) *(e +  r*secret), curve.n)
    
    r_id = kp.y & 1
    if kp.y > curve.n:
        r_id += 2
    
    return Signature(r, s, r_id)

# Handle client connection
def handle_client(client_socket):
    # generate private_key and public_key
    private_key = PrivateKey()
    public_key = private_key.generate_public_key()
    print(public_key)

    # Prepare the data to be sent
    while True:
        try:
            string = input("Enter a message to send to the client: ")
            message = bytes(string, 'utf-8')
            signature = sign(private_key, message)
            print(signature)

            pk = {
                "px": public_key.p.x,
                "py": public_key.p.y
            }
            signature_data = {
                "r": signature.r,
                "s": signature.s,
                "r_id": signature.r_id
            }

            data = {
                "public_key": pk,
                "signature": signature_data,
                "message": string
            }

            json_data = json.dumps(data)

            # Send the JSON data to the client
            client_socket.send(json_data.encode())

            # Receive data from the client
            response = client_socket.recv(1024).decode()
            if not response:
                break
            print("Received from client:", response)

        except ConnectionResetError:
            break

    # Close the connection
    client_socket.close()

# Create a socket object
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Get the local machine name and choose a port
host = socket.gethostname()
port = 8888

# Bind the socket to the port
server_socket.bind((host, port))

# Listen for incoming connections
server_socket.listen(10)

print("Server is listening on port", port)

# Accept multiple clients
while True:
    client_socket, addr = server_socket.accept()
    print("Client connected from:", addr)
    client_handler = threading.Thread(target=handle_client, args=(client_socket,))
    client_handler.start()
