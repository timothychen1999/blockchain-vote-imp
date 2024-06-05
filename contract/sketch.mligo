module Sketches = struct
  type storage = {
    res: bytes;
    num_res: nat;
    len: nat;
  }
  type return = operation list * storage

  [@entry] let hash (i : nat) (s : storage) : return = 
  let ib : bytes = bytes i
  in let ibe : bytes = ib lor 0x0000000000000000
  in let hibe : bytes = Crypto.sha256 ibe
  in [],{res = hibe; len = Bytes.length ibe; num_res=nat hibe}

  

  

end