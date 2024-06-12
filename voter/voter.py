from typing import List, Tuple, Callable, Literal
import secrets
import math
import hashlib
import sys

sys.setrecursionlimit(10**6)


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

def fast_modexp(base:int,exp:int,mod:int) -> int:
    """Fast modular exponentiation."""
    result = 1
    base = base % mod
    while exp > 0:
        if exp % 2 == 1:
            result = (result * base) % mod
        exp = exp >> 1
        base = (base * base) % mod
    return result

class Voter:

        
    def __init__(self, **kwargs):
        """Construct Voter with default settings and random key."""
        self.choice_length : int = 128   # in bytes
        self.mask_length : int = 128       # in bytes
        self.ident : any = None
        self.mask: int = None
        self.mask_inv: int = None
        for key, value in kwargs.items():
            if key == 'choice_length':
                self.choice_length = value
            elif key == 'mask_length':
                self.mask_length = value
            elif key == 'ident':
                self.ident = value

    def receive_enc_pairs(self,ep: List[Tuple[int,int]]) -> None:
        self.enc_pairs = ep
    def generate_mask(self,rsa_n:int) -> None:
                # Generate a random mask

        while True:
            mask = secrets.randbits(self.mask_length*8) % rsa_n
            if mask > 1 and math.gcd(mask,rsa_n) == 1:
                break
        self.mask = mask
        self.mask_inv = modinv(mask,rsa_n)
    
    def generate_ballot(self,rsa_n:int,rsa_v:int,hash:Callable[[bytes],bytes]|Literal["sha256","sha512"] = "sha256") -> Tuple[int,int]:
        """Generate a ballot with the given RSA public key and hash function.
        
            hash - can be given in name (SHA256, SHA512) or as function.
        """
        
        
        _hash: Callable[[bytes],bytes]
        if type(hash) == str:
            match hash:
                case "sha256":
                    _hash = lambda x : hashlib.sha256(x).digest()
                case "sha512":
                    _hash = lambda x : hashlib.sha512(x).digest()
                case _:
                    raise Exception("Invalid hash function.")
        else:
            _hash = hash
        
        if self.mask is None or self.mask_inv is None:
            self.generate_mask(rsa_n)
        
        mask = self.mask
        assert mask is not None and mask > 1
        
        
        if self.enc_pairs is None:
            raise Exception("No encrypted pairs received.")

        
        # Generate the ballot
        b1orig,b2orig = self.enc_pairs[0]
        b1hash,b2hash = _hash(b1orig.to_bytes(self.choice_length,"big")+mask.to_bytes(self.mask_length,"big")),_hash(b2orig.to_bytes(self.choice_length,"big")+mask.to_bytes(self.mask_length,"big"))
        b1,b2 = int.from_bytes(b1orig.to_bytes(self.choice_length,"big")+b1hash,"big"),int.from_bytes(b2orig.to_bytes(self.choice_length,"big")+b2hash,"big")
        # print("b2",b2)
        assert b1 < rsa_n and b2 < rsa_n
        return (b1*pow(mask,rsa_v,rsa_n))%rsa_n,(b2*pow(mask,rsa_v,rsa_n))%rsa_n
             
