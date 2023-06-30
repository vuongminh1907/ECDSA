import socket
import json
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
    def read(path:str) -> str:
        with open(path, "r") as file:
            return file.read()

    @classmethod
    def write(path:str, message:str) -> None:
        with open(path, "w") as file:
            file.write(message)

    @classmethod
    def append(path:str, message:str) -> None:
        with open(path, "a") as file:
            file.write(message)

    @classmethod
    def get_size(path:str) -> int:
        pass

class Converter:
    @classmethod
    def hex_to_string(h:hex) -> str:
        pass

    @classmethod
    def string_to_hex(s:str) -> hex:
        pass

class Point:
    def __init__(self, x:int, y:int) -> None:
        self.x = x
        self.y = y
    
    def __str__(self) -> str:
        return f"({self.x}, {self.y})"

class Curve:
    """

    y^2 = x^3 + ax + b

    params:
        name -> curve name
        a, b -> curve paramets
        p    -> field
        g    -> generator point
        n    -> number of points generate by scalar multiplication using the point g
    """
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

    def scalar_multiplication(self:object, k:int, p:Point) -> Point:
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
        0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
        0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8,
    ),
    n=0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
)

class PublicKey:
    def __init__(self:object, p:object, curve:object) -> None:
        self.p = p
        self.curve = curve

    def to_string(self:object, encoded=False) -> str:
        base = 2 * (1 + len("%x" % self.curve.n))

        x = str(hex(self.p.x)).zfill(base)
        y = str(hex(self.p.y)).zfill(base)

        if encoded:
            return "0004" + x + y
        return x + y 

    def from_strin(self:object) -> str:
        pass

    def to_der(self:object) -> str:
        pass

    def from_der(self:object) -> str:
        pass

    def __str__(self:object) -> str:
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
    def __init__(self:object, r:int, s:int, r_id:int):
        self.r = r
        self.s = s
        self.r_id = r_id

    def __str__(self:object) -> str:
        return f"r: {self.r} \ns: {self.s}\nr_id: {self.r_id}"
    
def verify(public_key:PublicKey, message:bytes, signature:Signature) -> bool:
    curve = public_key.curve
    q = public_key.p
    
    r = signature.r
    s = signature.s

    e = int(sha256(message).hexdigest(), 16)

    iv = inverse_mod(s, curve.n)
    u1 = reduce_mod(e * iv, curve.n)
    u2 = reduce_mod(r * iv, curve.n)

    p1 = curve.scalar_multiplication(u1, curve.g)
    p2 = curve.scalar_multiplication(u2, q)

    p3 = curve.add(p1, p2)
    
    return p3.x % curve.n == r

    
# Create a socket object
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Get the server IP address and port
server_ip = socket.gethostname()
server_port = 8888

# Connect to the server
client_socket.connect((server_ip, server_port))

# Receive data from the server
data = client_socket.recv(1024).decode()

# Parse the JSON data
received_data = json.loads(data)
signature = received_data["signature"]
message = received_data["message"]
public_key = received_data["public_key"]

# modify data from server
signature = Signature(signature["r"],signature["s"],signature["r_id"])
message = bytes(message, 'utf-8')
# remake public key
p = Point(public_key["px"], public_key["py"])
public_key = PublicKey(p,secp256k1)

# veryfi data 
print("Received message:", message)
valid_sign = verify(public_key, message, signature)
print("Verify information: ", valid_sign)
# Send a message to the server
message = "Thank for your information, that so great!"
client_socket.send(message.encode())

# Close the connection
client_socket.close()
