# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

Satochip applet full versions follows this format: vX.Y-Z.W where:
* X.Y refers to the PROTOCOL VERSION: changes that impact compatibility with the client side (e.g new functionalities, major patch...)
* Z.W refers to changes with no impact on compatibility of the client (e.g minor patches, optimizations...)

## [0.16-0.0]

Work-in-progress version (NOT for production): security fixes and hardening patches following a security code review of the applet.
This version will be bumped to v0.16-0.1 once all identified issues have been patched and thoroughly tested.

* Fix ResetKey() 2FA check: the 2FA HMAC was computed over the wrong buffer (stale data in recvBuffer instead of the reset key's pubkey, which was itself stored in tmpBuffer and left unused). This made EC key reset unusable on 2FA-enabled cards. The pubkey is now correctly staged in recvBuffer before the HMAC computation.

* Add EC point validation for external pubkeys (SeedKeeper trusted pubkey and secure-channel client pubkey): points are now checked to be canonically encoded and on the secp256k1 curve (Y^2 = X^3 + 7 mod p) before any EC operation. This mitigates invalid-curve attacks (Lim-Lee small subgroup attacks) against the authentikey (used for SeedKeeper secure seed import) and the secure channel ephemeral key.

* Fix 2FA bypass in Musig2SignHash(): when 2FA is enabled, the OP_FINALIZE step now requires the 2FA HMAC, like all other signing operations. The 2FA code is computed over the 32-byte nonce coefficient b (which commits to the MuSig2 session: aggnonce, aggpk, message) with a 32-byte 0xEE-padding, provided as [2FA-flag(2b) | hmac(20b)] after the signing data. The check is performed before the secnonce is validated, so a failed 2FA attempt does not burn the secnonce id. The per-operation 2FA padding constants are now documented in the code.

* Fix crash in Musig2GenerateNonce() after 32768 secnonce generations: the id-list index was computed with a modulo on a signed short counter, producing a negative array index (uncaught exception) once the counter overflowed, permanently breaking MuSig2 nonce generation and making the counter-overflow handler unreachable. The index is now computed with a bitmask, so the full 65535-id cycle works as documented: ids stay unique, the overflow handler is reached, the MAC key is rotated and the counter restarts at 1.

* Fix TaprootTweakPrivateKey() to comply with BIP341: the tagged hash was computed over the 32-byte **XOR** of `x(P)` and the tweak `h`, instead of the **concatenation** `x(P) || h` required by BIP341. Two consequences: the resulting tweak could not be reproduced by a standard implementation whenever `h` was non-zero (breaking script-path spending, which verifies the tweak at consensus level), and `t = H(x(P) XOR h)` did not bind the tweak to a specific internal key — for any pair `(P, h)` an attacker could compute `h' = x(P) XOR x(P') XOR h` yielding the same `t`, defeating the taproot commitment.
  * `p2=0x00` (TAPROOT_TWEAK) now performs the BIP341-compliant tweak. `tweak_size` may be 32 (h is the merkle root, 64 bytes hashed) or **0** (the output commits to no script tree, as in BIP86 key-path-only spending: h is the empty byte string and only the 32 bytes of `x(P)` are hashed).
  * **Existing key-path-only (BIP86) addresses are not affected.** The old XOR computation coincides with BIP341 exactly when `h` is all-zero, which is the case for key-path-only derivation, and that result is reproduced by the new `tweak_size=0` form. Clients that previously sent a 32-byte all-zero tweak should now send `tweak_size=0`; both yield the same key, and it is the BIP341-correct one (verified against the BIP86 test vectors).
  * **Incompatibility warning:** a tweak derived with a **non-zero** `h` (i.e. committing to a script tree) on v0.15-0.1 or earlier cannot be reproduced by this version and is no longer derivable on-card. Taproot was a beta feature in those versions, and the script path of such an output was never spendable anyway (consensus recomputes the BIP341 tweak), so this is expected to affect no one. Funds locked with a non-zero legacy tweak remain recoverable from the seed: either temporarily reinstall the v0.15-0.1 applet and sweep them, or compute the legacy tweak offline. The seed is necessarily available in that situation, since reinstalling the applet erases it and requires re-importing it.
  * `p2` is now validated: previously any value other than `0x00` silently bypassed the tweak (copying the private key as-is), so a client sending an unexpected `p2` would sign with the untweaked key. Unknown values now return `SW_INCORRECT_P2`.
  * The tweak operation now also respects `feature_schnorr_policy`, since a tweaked key is only usable for schnorr signatures. Previously only the bypass path (Nostr) checked a feature policy.

* Fix SignSchnorrHash() destroying the tweaked private key: the function borrowed the `taproot_tweakedkey` object as scratch storage to compute `R = rand*G` (`keyAgreement` needs an `ECPrivateKey` and there is no spare one) and never restored it. The tweaked key therefore survived exactly one signature, and every later signature was made with the **previous signature's nonce as its private key** — silently, returning a well-formed 64-byte signature that simply does not verify under the taproot output key. The tweaked secret is now saved before the nonce is staged and restored immediately after `R` is computed, so several hashes can be signed after a single TaprootTweakPrivateKey(), as is needed to sign the several inputs of one transaction. Beyond the correctness issue, the old behaviour published `s1 = k1 + e1*d` alongside a second signature whose secret is exactly `k1`, putting the tweaked private key one solved discrete log away instead of two. Clients that tweak before every signature (satochip_cli.py does) were not affected, which is why this went unnoticed.
  * SignSchnorrHash() now also checks that a tweaked key has actually been staged, instead of letting `keyAgreement.init()` throw an uncaught `CryptoException` (0x6F00) when none is. Signing before any TaprootTweakPrivateKey() call, or after a seed/factory reset, now returns `SW_INCORRECT_INITIALIZATION`.

* Complete resetToFactory()/resetSeed(): the MuSig2 state (secnonce encryption/MAC keys, list of valid secnonce ids, id counter) is now reset on both factory reset and plain seed reset, so encrypted secnonces exported before the reset can no longer be used (a new resetMusig2NonceState() function is shared with the Musig2GenerateNonce() counter-overflow handler). The secure channel session key and the option flags are now also cleared on factory reset. The code now documents that the personalization PKI data (authentikey, certificate, personalizationDone flag) deliberately survives a factory reset.

* Harden ImportKey(): the imported private key scalar is now checked to be in range [1, n-1] for secp256k1, returning SW_INVALID_PARAMETER otherwise (previously an invalid scalar triggered an uncaught CryptoException from setS(), returning 0x6F00). Also fixed the error path for a wrong blob_size, which threw the blob_size value itself as status word (returning 0x9000, i.e. success, if blob_size was 0x9000) instead of SW_INVALID_PARAMETER.

* Use constant-time comparison for all MAC/HMAC verifications (2FA checks, secure channel MAC, secure import MAC): Util.arrayCompare() may return as soon as the first difference is found, providing a timing oracle that could allow byte-by-byte forgery of authentication codes, and there is no try counter limiting the number of attempts. A new arrayCompareConstantTime() function (XOR-accumulate over the full length, no early exit) is now used at all 11 authentication-check call sites. Comparisons over public data (tx hash, MuSig2 pubkey match, secret fingerprint) are unchanged.

* Code cleanup: removed ~25 redundant casts (on variables and constants already of the target type) that generated compiler warnings during the build. No functional change.

* Fix spurious select (see https://github.com/Toporin/SatochipApplet/issues/11)

* Harden signMessage() input validation: the 2-byte chunk_size in the OP_PROCESS and OP_FINALIZE data is now checked against the number of bytes actually received (and to be non-negative), returning SW_WRONG_LENGTH otherwise. Previously, a wrong chunk_size made the hash read stale APDU buffer content or throw an out-of-bounds exception (0x6F00).

* Enforce a minimum seed size in importBIP32Seed(): the seed size must now be in range [16, 64] bytes (BIP32 recommends at least 128 bits of entropy), returning SW_WRONG_LENGTH otherwise. Previously any size from 0 to 64 was accepted, including a degenerate empty seed. SeedKeeper imports (16-64 byte master seeds) are unaffected.

## [0.15-0.1]

MuSig2 support (experimental): add mechanism to ensure that the BIP327 encrypted secnonce cannot be reused.

This is implemented using a 2-byte counter starting from 1.
This counter is increment during each GenerateSecnonce() execution.
A unique id based on this counter is saved in the encrypted secnonce that is exported, and also stored in the chip in a list of valid ids.

During Musig2SignHash(), the id recovered from the decrypted secnonce is checked against the locally-stored list of valid ids.
If the id is found, the secnonce is considered valid and the id is removed from the list of valid ids to ensure it cannot be reused.
If the id is not found, the secnonce is considered invalid and an error is thrown.

When the counter overflows, we invalidate all encrypted secnonces by generating a new MAC key, and we reset the list of valid ids.

The maximum size of the id list (BIP327_MAX_NB_ID) determines the maximum number of MuSig2 sessions that can be performed in parallel.
Newly generated ids overwrite old entries in the list when the list reaches its maximum size.

We use a 2-byte counter to reduce the memory footprint.
After 65535 counter MuSig2 secnonce generations, the counter overflows and all existing secnonces are invalidated by changing the MAC key.
The counter then resets to 1 and Musig2GenerateNonce() can be invoked again.

## [0.15-0.0]

* MuSig2 support (experimental)

**Overview of MuSig2 Smartcard Implementation**

Given the resource limitations of smartcards (no display/button and constrained memory), we’ve implemented a partial 
version of the [BIP327 specification](https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki), 
specifically the following algorithms that involve the private key:

* **Nonce generation**: `NonceGen(sk, pk, aggpk, m, extra_in)`
* **Partial signing**: `Sign(secnonce, sk, session_ctx)`

**NonceGen:**

* The private key (`sk`) is derived from a seed imported onto the card during setup.
* The card uses the internal `sk`, along with wallet-provided data (`pk`, `aggpk`, 32-byte `m`, and 32-byte `extra_in`) and 32 bytes of internal randomness to generate the `pubnonce` and `secnonce`.
* The `pubnonce` is returned to the wallet, and the `secnonce` is encrypted using a random 16-byte key only known to the card.
* Exporting the encrypted `secnonce` avoids having to store it in card memory, enabling multiple parallel `NonceGen()` sessions.

**Sign:**

* The wallet sends back the encrypted `secnonce` and session context data to the card.
* The card decrypts the `secnonce`, verifies it matches the expected public key, and performs the signing operation using its internal private key.
* The final output is the 32-byte `psig`.

Due to limited card resources, some session context data is preprocessed externally by the wallet. The card requires the following inputs (as per BIP327 notation):

* `b` (32 bytes)
* `e*a mod n` (32 bytes)
* `has_even_y(R)` (1 byte)
* `g*gacc` (1 byte)

Note: The smartcard performs blind signing, so limited checks are possible on the session context data. The card internally computes:
`psig = (k1 + b*k2 + e*a*d) mod n`.

This implementation has been validated against the relevant [BIP327 test vectors](https://github.com/bitcoin/bips/tree/master/bip-0327).

## [0.14-0.5]

* Add policy to enable/disable various optional features
  * Features can be enabled, disabled or blocked through apdu command (INS 0x3A)
  * Current features: Schnorr signatures, Nostr event signing (bypass key tweak required by Taproot), Liquid-Bitcoin support through Master Blinding Key export
  * Principle is roughly the same as for NFC policy: a feature can be enabled, disabled or blocked
  * If a feature is blocked, it can be reenabled only by a factory reset

## [0.14-0.4]

* Add support for NFC policy:
  * NFC interface can be disabled or blocked through apdu command (INS 0x3E).
  * By default, NFC is enabled. NFC policy can only be changed via the contact interface.
  * Changing NFC policy requires to validate PIN first.
  * NFC Policy:
    * NFC_ENABLED=0; // enabled by default
    * NFC_DISABLED=1; // can be re-enabled at any time
    * NFC_BLOCKED=2; // cannot be re-enabled except with reset factory!

## [0.14-0.3]

* Add Liquid-Bitcoin support:
  * export Master Blinding Key (new instruction: 0x7D)
  * The master blinding key is derived from the seed, and is itself used to derive deterministic blinding keys for each address derivation path.
  * For each blinded output, the wallet must know the corresponding blinding key/s in order to unblind the asset type and amount.
  * Master Blinding Key derivation is based on https://github.com/satoshilabs/slips/blob/master/slip-0077.md

## [0.14-0.2]
* Schnorr signature: add option to bypass key tweaking (beta)
  * Some schemes like Taproot require key tweaking, others (like Nostr) don't.
  * For TaprootTweakPrivateKey (ins 0x7c) use p2: 0x00 for key tweak, 0x01 to bypass tweak

* Update build using javacard sdks github repo submodule
  * Use `git submodule update --init --recursive`

## [0.14-0.1]

* BIP340 Schnorr signature:
  * new instruction 0x7b (SignSchnorrHash)   
  * This function signs a given hash with a std or the last Taproot tweaked key
  * If 2FA is enabled, a HMAC must be provided as an additional security layer.
  * Before using this method to sign a tx hash, a tweaked privkey must be derived  from a (BIP32 or simple) privkey using TaprootTweakPrivateKey().
  
```
  ins: 0x7B
  p1: 0x00
  p2: 0x00
  data: [hash(32b) | option: 2FA-flag(2b)|hmac(20b)]
  return: [sig]
```

* TAPROOT: Add method TaprootTweakPrivateKey(APDU apdu, byte[] buffer)
  * new instruction 0x7c 
  * This function generates a tweaked private keys, as used in Bitcoin taproot (TapTweak).
  * See https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki
  * See also https://bitcoinops.org/img/posts/taproot-workshop/taproot-workshop.pdf
  * A private key must first be available, either from a keyslot or derived from a BIP32 seed using getBIP32ExtendedKey().
  * The tweaked key is then stored in the same keyslot and available next for signing.
  * The function returns the corresponding public key coordx, self-signed
  
```
    ins: 0x7C
    p1: key number or 0xFF for the last derived Bip32 extended key
    p2: 0x00
    data: [tweak_size (1b) | tweak data (32b)]
    return: [coordx_size(2b) | coordx | sig_size(2b) | authentikey_sig]
```

## Previous versions

* 0.1-0.1: initial version
* 0.2-0.1: support for hmac-sha1 authorisation + improved sha256 + bip32 full support  
* 0.3-0.1: change parseTransaction response for coherence: add separate short flags for second factor authentication  
* 0.3-0.2: fast Sha512 computation  
* 0.4-0.1: getBIP32ExtendedKey also returns chaincode
* 0.5-0.1: Support for Segwit transaction
* 0.5-0.2: bip32 cached memory optimisation: fixed array instead of list 
* 0.6-0.1: bip32 optimisation: speed up computation during derivation of non-hardened child 
* 0.6-0.2: get_status returns number of pin/puk tries remaining
* 0.6-0.3: Patch in function SignTransaction(): add optional 2FA flag in data
* 0.7-0.1: add CryptTransaction2FA() to encrypt/decrypt tx messages sent to 2FA device for privacy
* 0.7-0.2: 2FA patch to mitigate replay attack when importing a new seed
* 0.8-0.1: add APDUs to reset the seed/eckey/2FA. 2FA required to sign tx/msg and reset seed/eckey/2FA. 2FA can only be disabled when all privkeys are cleared.
* 0.9-0.1: Message signing for altcoin. 
* 0.10-0.1: add method SignTransactionHash()
* 0.10-0.2: support for native sha512
* 0.10-0.3: ECkey recovery optimisation: support ALG_EC_SVDP_DH_PLAIN_XY
* 0.10-0.4: Cleanup: optimised code only, removed legacy sha512 implementation and slow pubkey recovery
* 0.11-0.1: support (mandatory) secure channel
* 0.12-0.1: Card label & Support for encrypted seed import from a SeedKeeper
* 0.12-0.2: 2FA can be disabled using reset2FAKey() without reseting the seed
* 0.12-0.3: SeedKeeper support: label & labelsize no longer required 
* 0.12-0.4: add reset to factory support
* 0.12-0.5: add support for personalisation PKI
