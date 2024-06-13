import sympy
import secrets
import math

class VA:
    
    def __init__(self, **kwargs):
        """Construct VA with default settings and random key."""
        self.keygen()
        
    
    # Benaloh keygen
    def keygen(self,N:int = 256,r : int = 10**9):
        """Generate the Benaloh public and private keys."""
        
        r = sympy.nextprime(r)
        
        i = secrets.randbelow(r-1)+1    # [1,r)        
        j = secrets.randbelow(r-2)+2    # [2,r)
        p=10
        while not sympy.isprime(p):
            alpha  = secrets.randbits(math.ceil(N/(math.log2(r)**2)))
            p = alpha*(r**2)+i*r+1
        q=10
        while not sympy.isprime(q):
            beta = secrets.randbits(math.ceil(N/(math.log2(r))))
            q = beta*r+j
        
        assert (p-1) % r == 0
        assert (p-1) % (r**2) != 0
        assert (q-1) % r != 0
        
        n = p*q
        
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
    def encryt (self,m:int) -> int:
        """Encrypt the message m."""
        assert 0 <= m  and m < self.r
        return pow(self.y,m,self.n)
