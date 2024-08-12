import hashlib
import sympy
import sys
import secrets
import math
from typing import List,Tuple,Dict
import pathlib
from Crypto.PublicKey import RSA

sys.setrecursionlimit(10**6)
padding : bytes = bytes.fromhex("003031300D060960864801650304020105000420")

def extended_gcd(a:int,b:int) -> Tuple[int,int,int]:
    """Extended Euclidean Algorithm to find the GCD and the coefficients of a,b."""
    if a == 0:
        return (b,0,1)
    else:
        g,y,x = extended_gcd(b % a, a)
        return (g,x - (b // a) * y,y)
def modinv(a:int,m:int) -> int:
    """Modular Inverse of a mod m."""
    g,x,y = extended_gcd(a,m)
    if g != 1:
        raise Exception("Modular inverse does not exist.")
    else:
        return x % m
class Beacon:
    def __init__(self):
        self.storage: Dict[str, List[bool]] = {}
    def get_bits(self,n: int,seed) -> List[bool]:
        if seed not in self.storage:
            self.storage[seed] = [bool(int(x)) for x in f"{secrets.randbits(n):b}"]
        return self.storage[seed]


class VA:
    
    def __init__(self, **kwargs):
        """Construct VA with default settings and random key."""
        self.keygen()
        self.rsa = RSA.generate(4096)
    
    # Benaloh keygen
    def keygen(self,N:int = 64*8,r : int = 10**9):
        """Generate the Benaloh public and private keys."""
        
        r = sympy.nextprime(r)   
        i = secrets.randbelow(r-1)+1    # [1,r)        
        j = secrets.randbelow(r-2)+2    # [2,r)
        p=10
        while not sympy.isprime(p):
            alpha  = secrets.randbits(math.ceil(N/(math.log2(r)*2)))
            p = alpha*(r**2)+i*r+1
            
        q=10
        while not sympy.isprime(q):
            beta = secrets.randbits(math.ceil(N/(math.log2(r))))
            q = beta*r+j
        
        
        assert (p-1) % r == 0
        assert (p-1) % (r**2) != 0
        assert (q-1) % r != 0
        
        n = p*q
        
        print (math.log2(n),math.log2(p),math.log2(q))
        
        while True:
            y = secrets.randbelow(n-1)+1   # [1,n)
            if math.gcd(y,n) == 1 and pow(y,(p-1)*(q-1)//r,n) != 1:
                self.y = y
                break
        self.n = n
        self.r = r
        self.N = N
        self.p = p
        self.q = q
    def encrypt (self,m:int) -> int:
        """Encrypt the message m."""
        
        if not ( 0 <= m and m < self.r):
            raise Exception("Invalid message.")
        x = self.n
        while math.gcd(x,self.n) != 1:
            x = secrets.randbelow(self.n-1)+1
        assert x != 0
        assert self.y != 0
        #print (pow(self.y,m,self.n),pow(x,self.r,self.n))
        
        return (pow(self.y,m,self.n)*pow(x,self.r,self.n)) % self.n
    def decrypt_with_cert (self,z:int) -> Tuple[int,int]:
        """Decrypt the ciphertext z."""
        
        if not ( 0 < z and z < self.n):
            raise Exception("Invalid ciphertext.")
        y_inv = modinv(self.y,self.n)
        
        d = -1
        for m in range(0,self.r):
            zym = z * pow(y_inv,m,self.n)
            zym %= self.n
            if pow(zym,(self.p-1)*(self.q-1)//self.r,self.n) == 1:
                d = m
                break
        assert d != -1
        A = modinv(self.r,(self.p-1)*(self.q-1)//self.r)
        u = pow(zym,A,self.n)
        s = self.n
        while math.gcd(s,self.n) != 1:
            s = secrets.randbelow(self.n-1)+1
        v = (u * pow(s,(self.p-1)*(self.q-1)//self.r,self.n)) % self.n
        return (d,v)
    def generate_enc_pair(self) -> List[Tuple[int,int]]:
        """Generate an encryption pair."""
        
        return [(max(ep),min(ep)) for ep in [(self.encrypt(0),self.encrypt(1)) for _ in range(self.N+1)]]
    def get_commitment(self,enc_pair:List[Tuple[int,int]]) -> List[int]:
        """Get the commitment of the encryption pairs."""
        return [self.decrypt_with_cert(ep[0])[0] for ep in enc_pair]
    def sign_ballot(self,ballot:Tuple[int,int])->Tuple[int,int]:
        b1,b2 = ballot
        # Check if the ballot is valid
        
        b1b, b2b = int.to_bytes(b1,512,"big"), int.to_bytes(b2,512,"big")
        h1,h2 = padding+hashlib.sha256(b1b).digest(),padding+hashlib.sha256(b2b).digest()
        assert self.rsa.can_sign()
        ih1,ih2 = int.from_bytes(h1,"big"),int.from_bytes(h2,"big")
        return (pow(ih1,self.rsa.d,self.rsa.n),pow(ih2,self.rsa.d,self.rsa.n))
        
    def get_rsa_public_key(self)->Tuple[int,int]:
        """Return the RSA public key."""
        return (self.rsa.n,self.rsa.e)   
    def get_interactive_proof(self,b : Beacon,enc_pair:List[Tuple[int,int]]) -> Tuple[int,List[Tuple[Tuple[int,int],Tuple[int,int]]]]:
        """Get the interactive proof of the encryption pairs."""
        # Drop the first pair
        fp = enc_pair[0]
        enc_pair = enc_pair[1:]
        seed = secrets.randbits(256)
        beacon_output = b.get_bits(seed=seed,n=len(enc_pair))
        result = []
        for ep, bit in zip(enc_pair,beacon_output):
            if bit:
                result.append(self.decrypt_with_cert(ep[0]),self.decrypt_with_cert(ep[1]))
            else:
                fp0inv = modinv(fp[0],self.n)
                fp1inv = modinv(fp[1],self.n)
                s1 = (self.decrypt_with_cert(ep[0]*fp0inv%self.n),self.decrypt_with_cert(ep[1]*fp0inv%self.n))
                s2 = (self.decrypt_with_cert(ep[0]*fp1inv%self.n),self.decrypt_with_cert(ep[1]*fp1inv%self.n))
                result.append(s2 if s1[0][0]==0 else s1)           
        return (seed,result)
    def dump_key(self,filename:str="./test/va-key") -> None:
        """Dump the Benaloh key to a file."""
        pathlib.Path(filename).parent.mkdir(parents=True, exist_ok=True)
        pathlib.Path(filename).unlink(missing_ok=True)
        with open(filename,"w") as f:
            f.write(f"{self.n}\n{self.y}\n{self.r}\n{self.p}\n{self.q}\n")
    def load_key(self,filename:str="./test/va-key") -> None:
        """Load the Benaloh key from a file."""
        with open(filename) as f:
            self.n,self.y,self.r,self.p,self.q = map(int,f.read().split())
    