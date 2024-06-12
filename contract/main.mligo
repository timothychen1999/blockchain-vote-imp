module Tally = struct
  type rsa_key = {
    n : nat;
    v : nat;
  }
  type vote_params = {
    v : nat;
    mask : nat;
    mask_inv : nat;
  }
  type decrypted_vote = {
    raw_vote : nat;
    hash : bytes;
  }

  type storage = {
    admin : address;
    rsa_key : rsa_key;
    vote_state : nat;
    vote_count : nat;
    n : nat;
    status : nat;
  }

  type return = operation list * storage

  (* Helper functions *)
  (*Fast modexp*)
  let fastmodexp (base: nat) (exp : nat) (m : nat) : nat =
    let rec fastmodexp_ (base: nat) (exp : nat) (m : nat) (acc : nat) : nat =
      if exp = 0n then
        acc
      else if exp mod 2n = 0n then
        fastmodexp_ (base * base mod m) (exp / 2n) m acc
      else
        fastmodexp_ (base * base mod m) (exp / 2n) m (acc * base mod m)
    in
    fastmodexp_ base exp m 1n

  (* Entrypoints *)

  [@entry] let set_n (nv : nat) (store : storage) : return = 
  let () = 
    if nv <= 1n then
      failwith "n must be greater than 1"
    in 
    [], {store with n = nv}
  [@entry] let set_rsa_key (key : rsa_key) (store : storage) : return =
  [], {store with rsa_key = key}
  [@entry] let vote (vp : vote_params) (store :storage) : return =
  let unmasked: nat = 
    (vp.v * vp.mask_inv) mod store.rsa_key.n 
  in
  let decrypted: nat = 
    fastmodexp unmasked store.rsa_key.v store.rsa_key.n
  in
  let dbytes: bytes = bytes decrypted lxor 0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
  in
  let () =
    if Bytes.length dbytes <> 160n then
      failwith "Invalid length"
  in
  let raw_vote_bytes: bytes =  (Bytes.sub 0n 128n dbytes)
  in
  let decrypted_vote: decrypted_vote = 
    {
      raw_vote = nat raw_vote_bytes;
      hash = Bytes.sub 128n 32n dbytes;
    }
  in
  let mask_bytes : bytes = 
    bytes vp.mask lxor 0x0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
  in
  let vm: bytes =
    Bytes.concat raw_vote_bytes mask_bytes
  in
  let () = 
    if decrypted_vote.hash <> Crypto.sha256 vm then
      failwith "Invalid vote hash"
  in 
  let () =
    if (vp.mask * vp.mask_inv) mod store.rsa_key.n <> 1n then
      failwith "Invalid vote format"
  in
  let choice : nat =
    decrypted_vote.raw_vote
  in
  [], {store with vote_state = choice; vote_count = store.vote_count + 1n}





end