from typing import List, Tuple, Callable, Literal
import secrets
import math
import hashlib

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


class Voter:
    def __init__(self):
        """Construct Voter with default settings and random key."""
        self.choice_length : int = 4    # in bytes
        self.mask_length : int = 4       # in bytes
        self.ident : any = None
        self.enc_pairs: List[Tuple[int,int]] = None
        
    def __init__(self, **kwargs):
        """Construct Voter with default settings and random key."""
        self.choice_length : int = 4    # in bytes
        self.mask_length : int = 4       # in bytes
        self.ident : any = None
        for key, value in kwargs.items():
            if key == 'choice_length':
                self.choice_length = value
            elif key == 'mask_length':
                self.mask_length = value
            elif key == 'ident':
                self.ident = value

    def receive_enc_pairs(self,ep: List[Tuple[int,int]]) -> None:
        self.enc_pairs = ep
    def generate_ballot(self,rsa_n:int,rsa_v:int,hash:Callable[[bytes],bytes]|Literal["sha256","sha512"] = "sha256") -> Tuple[int,int]:
        """Generate a ballot with the given RSA public key and hash function.
        
            hash - can be given in name (SHA256, SHA512) or as function.
        """
        
        mask : int
        _hash: Callable[[bytes],bytes]
        
        if self.enc_pairs is None:
            raise Exception("No encrypted pairs received.")
        # Generate a random mask
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
        
        while True:
            mask = secrets.randbits(self.mask_length*8) % rsa_n
            if mask > 1 and math.gcd(mask,rsa_n) == 1:
                break
        self.mask = mask
        self.mask_inv = modinv(mask,rsa_n)
        
        # Generate the ballot
        b1orig,b2orig = self.enc_pairs[0]
        b1hash,b2hash = _hash(b1orig.to_bytes(self.choice_length,"big")+mask.to_bytes(self.mask_length,"big")),_hash(b2orig.to_bytes(self.choice_length,"big")+mask.to_bytes(self.mask_length,"big"))
        b1,b2 = int.from_bytes(b1orig.to_bytes(self.choice_length,"big")+b1hash,"big"),int.from_bytes(b2orig.to_bytes(self.choice_length,"big")+b2hash,"big")
        return (b1*((self.mask**rsa_v)%rsa_n))%rsa_n,(b2*((self.mask**rsa_v)%rsa_n))%rsa_n
             
