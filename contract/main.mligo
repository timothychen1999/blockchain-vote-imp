module Tally = struct
  type rsa_key = {
    n : nat;
    v : nat;
  }
  type vote_params = {
    v : nat;
    mask_inv : nat;
  }
  type storage = {
    rsa_key : rsa_key;
    vote_state : nat;
    vote_count : nat;
    n : nat;
  }
  type return = operation list * storage



  (* Three entrypoints *)

  [@entry] let set_n (nv : nat) (store : storage) : return = 
  let () = 
    if nv <= 1n then
      failwith "n must be greater than 1"
    in 
    [], {store with n = nv}
  [@entry] let set_rsa_key (key : rsa_key) (store : storage) : return =
  [], {store with rsa_key = key}
  [@entry] let vote (vp : vote_params) (store :storage) : return =
  let decrypted: nat = 
    vp.v
  in
  [], {store with vote_state = decrypted; vote_count = store.vote_count + 1n}

  (* Helper functions *)

end