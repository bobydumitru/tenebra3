# TSC-1 Authorization Proof Specification (v1 candidate)

## Scope

This document specifies the implemented two-row linkable proof used by
`AuthorizationProof`. It is a candidate specification for external review, not
a cryptographic security certificate.

## Groups and commitments

The implementation uses Ristretto over the `curve25519-dalek` basepoint `B`.
Let `H_p(P)` be `hash_point(P)`, obtained by domain-separated SHA-512 and
`RistrettoPoint::from_uniform_bytes`. Let `B_r` be the Bulletproofs blinding
generator.

For ring member $i$:

- $P_i$ is the one-time destination public key;
- $D_i = H_p(P_i)$;
- $C_i = commitment_i - pseudo_output$;
- $I$ is the key image, encoded as a non-identity Ristretto point;
- $x$ is the secret for exactly one member $s$, with $P_s = xB$;
- $z$ is the blinding difference, with $C_s = zB_r$.

The key image is derived as $I = xH_p(P_s)$.

## Transcript

For transaction signing hash $m$, key image $I$, ring position $i$, and points
$L$, $R$, $T$, the challenge is:

$$
 c_{i+1} = H_s(\texttt{TSC-1:mlsag:challenge:v1} || m || I ||
 i_{LE32} || L || R || T) \pmod l
$$

The transcript binds the transaction unsigned encoding, key image, position and
both proof rows. The transaction network ID, version, expiry, inputs, outputs
and fee are included by the signing hash through canonical unsigned encoding.

## Signing equations

For non-signer positions, the signer samples responses $a_i,b_i$ and computes:

$$
 L_i = a_iB + c_iP_i,\quad
 R_i = a_iD_i + c_iI,\quad
 T_i = b_iB_r + c_iC_i.
$$

For the signer, fresh values $\alpha,\beta$ are used and the responses are:

$$
 a_s = \alpha - c_sx,\qquad b_s = \beta - c_sz.
$$

The challenge cycle closes when recomputation returns the initial challenge.

## Verification obligations

A verifier must reject unless all of the following hold:

- ring length is exactly 16 and member IDs are strictly ordered;
- every resolved destination, commitment and key image is a valid non-identity
  Ristretto point;
- the key image is unique in the transaction/state;
- every output range proof, commitment balance and fee is valid;
- the ring members resolve to committed on-chain outputs;
- reward maturity and transaction expiry pass;
- the challenge cycle closes for both rows;
- the staged state applies atomically and rejects replay.

## Security claims intentionally not made

The equations and implementation do not by themselves establish a formal proof
of soundness, anonymity, unlinkability, non-malleability or inflation
resistance. Those claims require a proof review, explicit assumptions, and
independent cross-implementation vectors.
