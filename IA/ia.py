from typing import Callable, Tuple
import Crypto.PublicKey.RSA as RSA
import pathlib
class IA:
    def __init__(self):
        """Construct IA with default settings and random key."""
        # Constructor code here
        self.verify_ident:Callable[[any],bool] = lambda x: True
        # RSA keygen
        self.rsa_key = RSA.generate(4096)

        
        pass
    def set_verify_ident(self, verify_ident:Callable[[any],bool]):
        """Set the function to verify the identity of the user."""
        self.verify_ident = verify_ident
    def sign_ballot(self,ballot:Tuple[int,int],user_ident: any)->Tuple[int,int]:
        """Sign the ballot with the user identity."""
        if not self.verify_ident(user_ident):
            raise Exception("Invalid user identity.")

        b1,b2 = ballot
        b1,b2 = pow(b1,self.rsa_key.d,self.rsa_key.n),pow(b2,self.rsa_key.d,self.rsa_key.n)
        


        return (b1,b2)
    def get_rsa_public_key(self)->Tuple[int,int]:
        """Return the RSA public key."""
        return (self.rsa_key.n,self.rsa_key.e)
    def dump_key(self,filename:str="./test/ia-key") -> None:
        """Dump the RSA key to a file."""
        pathlib.Path(filename).parent.mkdir(parents=True, exist_ok=True)
        pathlib.Path(filename).unlink(missing_ok=True)
        with open(filename,'w') as f:
            f.write(self.rsa_key.export_key().decode())
    def load_key(self,filename:str="./test/ia-key") -> None:
        """Load the RSA key from a file."""
        with open(filename) as f:
            self.rsa_key = RSA.import_key(f.read())
        assert self.rsa_key.has_private()
    
