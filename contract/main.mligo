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
  type result_and_proof = {
    result : nat;
    proof : nat;
  }
  type init_params = {
    rsa_key : rsa_key;
    n : nat;
    r : nat;
    y : nat;
  }
  type state  =
  | Uninitialized
  | Started
  | Finished

  type storage = {
    admin : address;
    rsa_key : rsa_key;
    vote_state : nat;
    vote_count : nat;
    n : nat;
    r : nat;
    y : nat;
    status : state;
    result : nat;
    used_ballot : nat big_set;
  }

  type return = operation list * storage
  let uninitialized = Uninitialized
  let started = Started
  let finished = Finished
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
  let () = 
    if store.status <> Started then
      failwith "Vote must be initialized"
  in
  let new_used: nat big_set =
    if not (Big_set.mem vp.v store.used_ballot) then
      failwith "Vote duplicate"
    else 
      Big_set.add vp.v store.used_ballot
  in
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
  let invaild_choice : bool = 
    choice = 0n
  in
  let new_state : nat = 
    if store.vote_count = 0n then
      choice mod store.n
    else
      (store.vote_state * choice) mod store.n
  in
  if invaild_choice then
    [], {store with vote_count = store.vote_count}
  else
  [], {store with vote_state = new_state; vote_count = store.vote_count + 1n;used_ballot = new_used}

  [@entry] let init (param : init_params) (s : storage) : return = 
  let () = 
    if s.admin <> Tezos.get_source () then
      failwith "Only admin can initialize the vote"
  in
  [], {s with status = Started; vote_count = 0n; vote_state = 1n;rsa_key = param.rsa_key; n = param.n; r = param.r; y = param.y; used_ballot = Big_map.empty}

  [@entry] let finalize (rp: result_and_proof)(s : storage) : return =
  let () = 
    if s.status <> Started then
      failwith "Vote must be initialized"
  in
  let () = 
    if (fastmodexp rp.proof s.r s.n) * (fastmodexp s.y rp.result s.n) mod s.n <> s.vote_state then
      failwith "Invalid result"
  in
  [],{s with status = Finished; result = rp.result}

  [@view] let get_result() (s : storage) : nat = 
  let () = 
    if s.status <> Finished then
      failwith "Vote must be finished"
  in
  s.result
  



end