# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

Satochip applet full versions follows this format: vX.Y-Z.W where:
* X.Y refers to the PROTOCOL VERSION: changes that impact compatibility with the client side (e.g new functionalities, major patch...)
* Z.W refers to changes with no impact on compatibility of the client (e.g minor patches, optimizations...)

## [0.16-0.1]

Security fixes and hardening patches following a security code review of the applet.

The protocol version stays 0.16 for all the changes below. Client developers should read the breaking changes first: each one is detailed in the section where it belongs.

### Breaking changes (summary)

* **UnblockPIN (0x46):** the data format is now `[PUK_size(1b) | PUK | (optional) PIN_size(1b) | (optional) PIN]`; the previous format (`[PUK]` without size prefix) is refused. See *New features*.
* **Reset to factory (0xFD):** a single APDU (`P1=0xAA`, `P2=0x55`), sent through the secure channel. It does not require the PIN. See *Refactoring*.
* **Removed commands**, which now return `SW_INS_DEPRECATED` (0x9C26): ParseTransaction (0x71), SignTransaction (0x6F), signMessage (0x6E), CreatePIN (0x40), ListPINs (0x48), setBIP32AuthentikeyPubkey (0x75) and setBIP32ExtendedPubkey (0x74). Use SignTransactionHash (0x7A) instead of the signing commands. See *Removed and deprecated*.
* **Single PIN and PUK:** P1 must be 0x00 in VerifyPIN, ChangePIN and UnblockPIN; the pin1/ublk1 fields of setup are ignored; the GetStatus bytes for PIN1/PUK1 are always 0. See *Refactoring*.
* **TaprootTweakPrivateKey (0x7C):** the tweak is now BIP341-compliant. Key-path-only (BIP86) keys are unchanged (send `tweak_size=0`), but a tweak with a non-zero merkle root derived by v0.15-0.1 or earlier cannot be reproduced. Unknown P2 values are refused. See *Security fixes*.
* **Musig2SignHash (0x7F):** with 2FA enabled, OP_FINALIZE now requires the 2FA HMAC, and the two flag bytes must be 0x00 or 0x01. See *Security fixes*.
* **Derived keys are transient:** the BIP32 extended key (P1=0xFF) and the taproot tweaked key are cleared on deselect and card reset (e.g. loss of the NFC field). Derive the key (getBIP32ExtendedKey) and tweak it (TaprootTweakPrivateKey) in the same session as the signature, otherwise SignTransactionHash, TaprootTweakPrivateKey, SignSchnorrHash, Musig2GenerateNonce and Musig2SignHash with P1=0xFF return SW_INCORRECT_INITIALIZATION (0x9C13). See *Optimizations*.
* **Smaller changes:** importBIP32Seed refuses seeds shorter than 16 bytes; ImportKey into an initialized keyslot returns SW_ECKEYS_INITIALIZED_KEY (0x9C1A) instead of SW_INCORRECT_P1; several invalid inputs that used to return 0x6F00 or succeed now return a specific error (see *Bug fixes* and *Hardening*).

### Security fixes

* Fix 2FA bypass in Musig2SignHash(): when 2FA is enabled, the OP_FINALIZE step now requires the 2FA HMAC, like all other signing operations. The 2FA code is computed over `sha256(b | e*a | has_even_y(R) | g*gacc)` (the 66 bytes of signing data, as sent in the APDU) with a 32-byte 0xEE-padding, provided as [2FA-flag(2b) | hmac(20b)] after the signing data. The hash covers every client-provided input of the partial signature: approving the nonce coefficient b alone would not be enough, since a compromised host could pair an approved b with the `e*a` of another message, and with a co-signer it controls obtain a valid signature for that message. The 2FA app must recompute b, e, a and the flags from the session context (aggnonce, pubkeys, tweaks, message) rather than take them from the host. The two flag bytes must now be 0x00 or 0x01 (as sent by Satochip-Java), so that a signing context has a single encoding; other values return SW_INVALID_PARAMETER. The check is performed before the secnonce is validated, so a failed 2FA attempt does not burn the secnonce id. The per-operation 2FA padding constants are now documented in the code.

* Fix TaprootTweakPrivateKey() to comply with BIP341: the tagged hash was computed over the 32-byte **XOR** of `x(P)` and the tweak `h`, instead of the **concatenation** `x(P) || h` required by BIP341. Two consequences: the resulting tweak could not be reproduced by a standard implementation whenever `h` was non-zero (breaking script-path spending, which verifies the tweak at consensus level), and `t = H(x(P) XOR h)` did not bind the tweak to a specific internal key — for any pair `(P, h)` an attacker could compute `h' = x(P) XOR x(P') XOR h` yielding the same `t`, defeating the taproot commitment.
  * `p2=0x00` (TAPROOT_TWEAK) now performs the BIP341-compliant tweak. `tweak_size` may be 32 (h is the merkle root, 64 bytes hashed) or **0** (the output commits to no script tree, as in BIP86 key-path-only spending: h is the empty byte string and only the 32 bytes of `x(P)` are hashed).
  * **Existing key-path-only (BIP86) addresses are not affected.** The old XOR computation coincides with BIP341 exactly when `h` is all-zero, which is the case for key-path-only derivation, and that result is reproduced by the new `tweak_size=0` form. Clients that previously sent a 32-byte all-zero tweak should now send `tweak_size=0`; both yield the same key, and it is the BIP341-correct one (verified against the BIP86 test vectors).
  * **Incompatibility warning:** a tweak derived with a **non-zero** `h` (i.e. committing to a script tree) on v0.15-0.1 or earlier cannot be reproduced by this version and is no longer derivable on-card. Taproot was a beta feature in those versions, and the script path of such an output was never spendable anyway (consensus recomputes the BIP341 tweak), so this is expected to affect no one. Funds locked with a non-zero legacy tweak remain recoverable from the seed: either temporarily reinstall the v0.15-0.1 applet and sweep them, or compute the legacy tweak offline. The seed is necessarily available in that situation, since reinstalling the applet erases it and requires re-importing it.
  * `p2` is now validated: previously any value other than `0x00` silently bypassed the tweak (copying the private key as-is), so a client sending an unexpected `p2` would sign with the untweaked key. Unknown values now return `SW_INCORRECT_P2`.
  * The tweak operation now also respects `feature_schnorr_policy`, since a tweaked key is only usable for schnorr signatures. Previously only the bypass path (Nostr) checked a feature policy.

* Fix SignSchnorrHash() destroying the tweaked private key: the function borrowed the `taproot_tweakedkey` object as scratch storage to compute `R = rand*G` (`keyAgreement` needs an `ECPrivateKey`) and never restored it. The tweaked key therefore survived exactly one signature, and every later signature was made with the **previous signature's nonce as its private key** — silently, returning a well-formed 64-byte signature that simply does not verify under the taproot output key. Beyond the correctness issue, the old behaviour published `s1 = k1 + e1*d` alongside a second signature whose secret is exactly `k1`, putting the tweaked private key one solved discrete log away instead of two. Clients that tweak before every signature (satochip_cli.py does) were not affected, which is why this went unnoticed.
  * The fix was first to save the tweaked secret and restore it after `R` was computed. `R` is now computed with the `ephemeral_privkey` scratch EC key instead (already used the same way in InitiateSecureChannel, ImportKey and Musig2GenerateNonce), so the tweaked key is never overwritten and this bug is structurally impossible; the signature output is identical. Several hashes can be signed after a single TaprootTweakPrivateKey(), as is needed to sign the several inputs of one transaction.
  * SignSchnorrHash() now also checks that a tweaked key has actually been staged, instead of letting `keyAgreement.init()` throw an uncaught `CryptoException` (0x6F00) when none is. Signing before any TaprootTweakPrivateKey() call, or after a seed/factory reset, now returns `SW_INCORRECT_INITIALIZATION`.

* Add EC point validation for external pubkeys (SeedKeeper trusted pubkey and secure-channel client pubkey): points are now checked to be canonically encoded and on the secp256k1 curve (Y^2 = X^3 + 7 mod p) before any EC operation. This mitigates invalid-curve attacks (Lim-Lee small subgroup attacks) against the authentikey (used for SeedKeeper secure seed import) and the secure channel ephemeral key.
  * importTrustedPubkey() refuses the pubkey (SW_UNSUPPORTED_FEATURE) on cards without the RSA engine used by Biginteger.mult_rsa_trick(). On those cards Secp256k1.isOnCurve() cannot check the curve equation and only checks that the coordinates are in range. The trusted pubkey is used in a static ECDH with the authentikey, and importEncryptedSecret() reveals whether a MAC computed with the shared key verifies, so an off-curve point would let an attacker recover the authentikey modulo small orders, one query at a time (invalid-curve attack). The secure channel keeps accepting such points: its card key is ephemeral and used only once.

* Use constant-time comparison for all MAC/HMAC verifications (2FA checks, secure channel MAC, secure import MAC): Util.arrayCompare() may return as soon as the first difference is found, providing a timing oracle that could allow byte-by-byte forgery of authentication codes, and there is no try counter limiting the number of attempts. A new arrayCompareConstantTime() function (XOR-accumulate over the full length, no early exit) is now used at all 11 authentication-check call sites. Comparisons over public data (tx hash, MuSig2 pubkey match, secret fingerprint) are unchanged.

* Log the PIN out when a secure channel is initiated: the PIN validation used to be cleared only on applet select/deselect, so it survived a new INIT_SECURE_CHANNEL in the same card session. Anyone sharing that session (e.g. another process on the same PC/SC reader) could open their own channel and use the PIN validated by the legitimate client, without knowing it. INIT_SECURE_CHANNEL now logs the PIN out and closes the previous channel first. Clients already verify the PIN after opening a channel, so they are not affected.

* Clear the MuSig2 state on reset: the secnonce encryption/MAC keys, the list of valid secnonce ids and the id counter are now reset on both factory reset and plain seed reset, so encrypted secnonces exported before the reset can no longer be used (a new resetMusig2NonceState() function is shared with the Musig2GenerateNonce() counter-overflow handler). The secure channel session key and the option flags are now also cleared on factory reset.

### Hardening

* Harden SignSchnorrHash() and Musig2SignHash() against side-channel and fault attacks:
  * The signatures compute s = k + e*d mod n in software (Biginteger): the private key and the nonces are processed byte by byte, multiplied with client-chosen values (e, and e*a for MuSig2, which the client provides directly) on the RSA engine as a public-key operation, and reduced with a division whose running time depends on the data. Each secret scalar x (private key, nonces) is now replaced with x + r*n for a fresh random r before entering the computation, which leaves the result mod n unchanged but randomizes all intermediate values, defeating power analysis (DPA) correlation and the timing of the final division.
  * The mask r is 119 bits (r < 2^119), the largest that Biginteger.mult_rsa_trick() supports: the blinded operands take 47 bytes, and (a + x')^2 < 2^754 stays below the 768-bit RSA modulus. A large mask makes single-trace recovery of r, or lattice attacks on a partially leaked r, much harder. The cost does not depend on the mask size, since mult_rsa_trick() always works on whole 96-byte buffers.
  * The result is computed twice, with independent blinding, deriving the private key and the nonces again from the key object and the secnonce in each round, and the two results are compared before anything is returned (SW_INTERNAL_ERROR on mismatch). A fault injected while d is processed would otherwise produce a signature that leaks d.
  * Biginteger.subtract() now computes the borrow without a branch, since it is used on secret values.
  * Cost: 6 multiplications on the RSA engine per Schnorr signature (was 1), 10 per MuSig2 partial signature (was 2).

* Constant-time arithmetic on secret scalars:
  * New Biginteger.lessThanCT(), isZeroCT() and addModCT() (no branch or early exit depending on the operand values) are now used for the BIP32 child key (IL check and IL + k mod n), the taproot tweak (seckey + t mod n) and the ImportKey() range check. The previous code branched on the carry and on comparisons with n, leaking one bit about the secrets per operation through timing.
  * SignSchnorrHash() checks the range of the BIP340 nonce (rand must be non-zero and below n) with isZeroCT() and lessThanCT(). equalZero() and lessThan() exit at the first differing byte, so their timing revealed when the top byte of the secret nonce was 0x00 or 0xFF: the kind of partial nonce leak that lattice attacks exploit.
  * TaprootTweakPrivateKey() negates the key with the copyScalar() helper (branching only on the public parity of P).

* Erase secrets once used: the shared secret and derived keys of the secure channel (recvBuffer[0..65)) and its ephemeral private key; the static ECDH secret and derived keys of importEncryptedSecret() (recvBuffer[0..105), on every exit), as well as the decrypted secret left in the APDU buffer; the 2FA secret and derived key in set2FAKey(); the imported private key left in the APDU buffer by ImportKey(); and the secret left in the scratch EC key (`ephemeral_privkey`) by ImportKey(), getBIP32ExtendedKey(), Musig2GenerateNonce() (the nonce k2) and SignSchnorrHash() (the nonce). The scratch EC key is only cleared when it is transient: a persistent fallback key would lose its curve parameters, which are only set again for transient keys.

* Check the curve parameters of every signing key before use (countermeasure against fault injection / curve substitution): previously applied only in getPublicKeyFromPrivate(), the check is now part of the keyslot helper getInitializedECKey() (see *Refactoring*), so all keyslot users benefit from it. It was then extended (through a new checkKeyCurve() helper) to the BIP32 extended key (P1=0xFF in SignTransactionHash, TaprootTweakPrivateKey, Musig2GenerateNonce, Musig2SignHash) and to the taproot tweaked key in SignSchnorrHash(), which were only checked to be initialized. A fault altering their curve parameters now returns SW_INCORRECT_ALG before the key is used.

* Make the factory reset safe against card tearing: the data is now erased with the secrets first (seed, BIP32 and taproot keys, keyslots), then the 2FA, and the setup flag last, the PIN objects being released after the setup flag is cleared. The 2FA used to be cleared first, so pulling the card right after that step left a seeded card with 2FA disabled, which defeats the purpose of 2FA for an attacker who knows the PIN. Each step only removes capabilities, and a torn reset never leaves a set-up card without PIN objects.

* Harden input validation:
  * setup() now validates its whole input before changing any state: every length field is checked against Lc (a malformed command used to read stale buffer bytes, or walk backwards with a negative size), and the PIN and PUK try limits must be in range [1, 16] (0 used to end in an uncaught PINException, and up to 127 tries were accepted). Only the fields up to the PUK are read; the deprecated fields that follow are ignored and may be omitted.
  * ImportKey(): the imported private key scalar is now checked to be in range [1, n-1] for secp256k1, returning SW_INVALID_PARAMETER otherwise (previously an invalid scalar triggered an uncaught CryptoException from setS(), returning 0x6F00).
  * importBIP32Seed() enforces a minimum seed size: the seed size must now be in range [16, 64] bytes (BIP32 recommends at least 128 bits of entropy), returning SW_WRONG_LENGTH otherwise. Previously any size from 0 to 64 was accepted, including a degenerate empty seed. SeedKeeper imports (16-64 byte master seeds) are unaffected.
  * importEncryptedSecret(): the encrypted_secret_size field is now checked to be positive and a multiple of the AES block size (16 bytes) before use (previously a value with the high bit set was read as a negative short, slipped past the length check, and caused negative-length exceptions). The PKCS#7 padding length read from the decrypted data is now also validated to be in range [1, 16] and not larger than the decrypted size, returning SW_INVALID_PARAMETER otherwise.
  * The command decrypted by the secure channel is now re-validated: its CLA must be the applet's (SW_CLA_NOT_SUPPORTED otherwise), its PKCS#7 padding must be valid, and its Lc must fit in the decrypted data without the padding (SW_WRONG_LENGTH otherwise), so that handlers no longer read stale APDU buffer content. A command without data may still be sent without Lc (`[CLA | INS | P1 | P2]`, as pysatochip does, e.g. for 0x73 and 0xAD): it is accepted with Lc = 0, instead of the first padding byte being read as Lc.
  * setFeaturePolicy() refuses an unknown feature id with SW_INCORRECT_P1, instead of returning success without doing anything.
  * signMessage(): the 2-byte chunk_size in the OP_PROCESS and OP_FINALIZE data was checked against the number of bytes actually received (and to be non-negative), returning SW_WRONG_LENGTH otherwise; a wrong chunk_size used to make the hash read stale APDU buffer content or throw an out-of-bounds exception (0x6F00). The command has since been removed (see *Removed and deprecated*).

### Bug fixes

* Fix ResetKey() 2FA check: the 2FA HMAC was computed over the wrong buffer (stale data in recvBuffer instead of the reset key's pubkey, which was itself stored in tmpBuffer and left unused). This made EC key reset unusable on 2FA-enabled cards. The pubkey is now correctly staged in recvBuffer before the HMAC computation.

* Fix crash in Musig2GenerateNonce() after 32768 secnonce generations: the id-list index was computed with a modulo on a signed short counter, producing a negative array index (uncaught exception) once the counter overflowed, permanently breaking MuSig2 nonce generation and making the counter-overflow handler unreachable. The index is now computed with a bitmask, so the full 65535-id cycle works as documented: ids stay unique, the overflow handler is reached, the MAC key is rotated and the counter restarts at 1.

* Remove the default PIN value, which could brick a card before setup: the PIN object is now null until setup() is called for the first time, where it is created (or simply updated on later setups). The default PIN field of the setup APDU is now ignored (but still parsed for backward compatibility), so setup() no longer requires knowledge of the default PIN. This eliminates a permanent brick scenario where the default PIN (only 3 tries) could be blocked before setup, making setup() impossible with no recovery path. Before setup, VerifyPIN() trivially succeeds and the personalization PKI commands skip the PIN check (pin != null guard), which is equivalent in practice to the previous public default PIN value. The PIN_INIT_VALUE constant was removed.

* Fix the PIN objects after a factory reset: the reset now resets and unblocks the PIN and PUK, restoring their try counters (OwnerPIN.update() does not reset them). On cards that support object deletion, it now releases the PIN/PUK objects, so the card is back to its fresh-install state and the next setup creates them with its own try limits; previously the objects were kept and new try limits were silently ignored. On cards without object deletion, the objects are kept and reused, with the try limits of the first setup.

* Fix key re-import after a factory reset: clearKey() clears the curve parameters, so keyslots that previously held a key lost them and failed import. The new getUninitializedKey() helper (see *Refactoring*) (re)sets the secp256k1 curve parameters of the keyslot in all cases.

* Merge [PR #22](https://github.com/Toporin/SatochipApplet/pull/22) (thanks @kkdao): count the two-byte size prefix in importTrustedPubkey() (fixes [#21](https://github.com/Toporin/SatochipApplet/issues/21)). The length check compared Lc with pubkey_size alone, so a command with Lc = 65 or 66 passed and the 65-byte copy read past the command data, silently storing a corrupted trusted pubkey. Well-formed 67-byte commands behave exactly as before.

* Fix the ImportKey() error path for a wrong blob_size, which threw the blob_size value itself as status word (returning 0x9000, i.e. success, if blob_size was 0x9000) instead of SW_INVALID_PARAMETER.

* Fix the NDEF record size and format: the NDEF file [NLEN(2b) | record] is limited to 222 bytes, so that SET_NDEF (p2=0x01) can always return [size(1b) | file] through the secure channel (a 224-byte buffer used to accept a record that could not be read back). The capability container now declares this real maximum instead of 1024 bytes. NDEFApplet install parameters with a larger record are refused with SW_WRONG_LENGTH, instead of an ArrayIndexOutOfBoundsException. SET_NDEF (p2=0x00) now applies the same format check as the installer: a non-empty record whose NLEN matches its size, otherwise SW_INVALID_PARAMETER.

* Report errors instead of uncaught CryptoExceptions (0x6F00):
  * Signing with the last derived BIP32 key (P1=0xFF) before any getBIP32ExtendedKey() since the seed was imported now returns SW_INCORRECT_INITIALIZATION (SignTransactionHash, TaprootTweakPrivateKey, Musig2GenerateNonce, Musig2SignHash).
  * CryptTransaction2FA(): OP_PROCESS/OP_FINALIZE without an OP_INIT now return SW_INCORRECT_INITIALIZATION, and an OP_FINALIZE whose data is not a whole number of AES blocks returns SW_INVALID_PARAMETER.
  * TaprootTweakPrivateKey() returns SW_TAPROOT_TWEAK_ERROR if the tweaked key is 0, and SignSchnorrHash() returns SW_SCHNORR_INVALID_NONCE if the nonce hash is not smaller than n (both have a negligible probability).

* Fix spurious select (see https://github.com/Toporin/SatochipApplet/issues/11).

### New features

* Add GET_RANDOM (0x30) command: returns 1 to 64 random bytes per call generated on-card by the platform's secure random number generator, for use as additional entropy (seeds, encryption keys, passwords, ...). The command requires PIN validation and returns the bytes through the secure channel (encrypted); random bytes are generated directly into the APDU buffer to avoid any leakage of sensitive data held in shared working buffers. The command is gated by a new FEATURE_ID_RANDOM (4) feature policy (enabled by default; can be disabled or permanently blocked with setFeaturePolicy and reset by factory reset). GetStatus() now also returns the random feature policy as an additional byte (offset 17).

* Add an NDEF applet and the SET_NDEF (0x3F) command (ported from Seedkeeper-Applet): the CAP now contains a second applet, NDEFApplet, installed under the standard NFC Forum Type 4 AID D2760000850101. It serves a single NDEF record so that tapping the card on a phone opens a link, without any app installed. The default record is a universal link to https://satochip.io/quick-start/satochip/ (it works on both Android and iOS). The record is stored in a 223-byte buffer shared between the two applet instances (SharedMemory) and can be replaced either at install time through the NDEF applet install parameters, or at any time afterwards with the new SET_NDEF (0x3F) command (p2=0x00 to set, p2=0x01 to get). Like every other command, SET_NDEF requires the secure channel, a completed setup and a validated PIN. This is backward compatible: clients that do not know the new command are unaffected.

* Extend UnblockPIN(): a forgotten PIN can now be unblocked AND changed by providing the PUK code. The data format is now [PUK_size(1b) | PUK | (optional) PIN_size(1b) | (optional) PIN]: if a new PIN is provided, it replaces the forgotten one; if only the PUK is provided, the PIN is simply unblocked with its previous value. After a successful unblock, the PIN and PUK try counters are restored. All inputs are validated before any state change and the PUK is checked with its exact length. **Compatibility note:** the previous format ([PUK] without size prefix) is not accepted anymore, clients must be updated.

* Return card status on card select (ported from Seedkeeper-Applet commit [01bc193](https://github.com/Toporin/Seedkeeper-Applet/commit/01bc19376fdc2dd22de4a265ddacb401a709f98f)): the SELECT APDU response now includes the same data as a GET_STATUS command (applet version, PIN/PUK tries remaining, 2FA/seeded/setup flags, NFC & feature policies), saving a round trip for clients. GetStatus() no longer checks P1/P2, since the SELECT command carries its own parameters (P1=0x04). This information was already available to anyone through the unauthenticated GET_STATUS command, so nothing new is disclosed.

* Improve authentikey management (ported from Seedkeeper-Applet commit [29ce8f0](https://github.com/Toporin/Seedkeeper-Applet/commit/29ce8f0984dd6ae02e0689ccf339f3b2865bc543)): the InitiateSecureChannel() response now also returns the authentikey coordx ([coordx_size(2b) | authentikey_coordx] appended), allowing non-ambiguous recovery of the authentikey public key from the signature. The PIN requirement is removed from getAuthentikey() (ins 0xAD) and export_PKI_pubkey() (ins 0x98), since the authentikey public key is public data that can already be recovered from the secure channel initiation. The legacy INS_BIP32_GET_AUTHENTIKEY (ins 0x73) is now served by getAuthentikey() too (see *Removed and deprecated*).

### Removed and deprecated

* Remove the ParseTransaction (0x71) and SignTransaction (0x6F) commands: they are deprecated and now return SW_INS_DEPRECATED (0x9C26) when invoked. Clients should use SignTransactionHash (0x7A) to sign transaction hashes (the client computes the sighash itself) and perform any transaction parsing off-card. Related code and objects are also removed: the Transaction.java parser class, the transactionData state (cached tx hash and cumulative amount for the 2FA limit), the PARSE_STD/PARSE_SEGWIT constants, the SW_INCORRECT_TXHASH status word, the "Tx approval" 2FA code entry, and the now-unused Biginteger methods swap/getLSB/subtract1_carry. The 2FA amount_limit field is still accepted in setup for protocol compatibility but is now deprecated and unused.

* Remove the signMessage (0x6E) command: it is deprecated and now returns SW_INS_DEPRECATED (0x9C26) when invoked. Clients should use SignTransactionHash (0x7A) to sign the (double-hashed) message hash instead, computing the message hash off-card. Related code and objects are also removed: the signMessage() function, the BITCOIN_SIGNED_MESSAGE_HEADER constant, the sign_flag multi-chunk state, the "Msg signing" 2FA code entry, and the Biginteger VarInt helpers (encodeVarInt, encodeShortToVarInt, isStrictlyLessThanUnsigned) as well as the dead Shift1bit/setZero/setByte methods (the latter already unused).

* Remove the CreatePIN (0x40) and ListPINs (0x48) commands, which now return SW_INS_DEPRECATED (see the single PIN/PUK refactoring below).

* Remove the setBIP32AuthentikeyPubkey (0x75) and setBIP32ExtendedPubkey (0x74) commands, which now return SW_INS_DEPRECATED. They let the client store externally computed public keys in the BIP32 cache, to speed up non-hardened derivation; they had been no-ops (returning two zero bytes) since the public keys are computed on-card with ALG_EC_SVDP_DH_PLAIN_XY, and the BIP32 cache is gone (see *Refactoring*).

* Merge getBIP32AuthentiKey() (ins 0x73) into getAuthentikey() (ins 0xAD): both instructions now return the authentikey, self-signed. getBIP32AuthentiKey() dates from when the authentikey was derived from the seed, and required a validated PIN and a seeded card. The authentikey is now generated at install and is public data, so ins 0x73 no longer requires the PIN. It still returns SW_BIP32_UNINITIALIZED_SEED (0x9C14) on an unseeded card, since legacy clients (pysatochip's card_bip32_get_authentikey()) use that error to detect the seed state. New clients should use ins 0xAD, and read the seed state from GET_STATUS. The computeAuthentikey() helper is merged into getAuthentikey(), which importBIP32Seed() also uses for its response.

* Deprecate the getBIP32ExtendedKey() p2 option flags (0x80 reset cache, 0x40 optimize non-hardened derivation, 0x20 store key as object), now silently ignored since the BIP32 cache is gone (see *Refactoring*).

### Optimizations

* Use transient (RAM) AES session keys for the secure channels (ported from Seedkeeper-Applet commit [87922ed](https://github.com/Toporin/Seedkeeper-Applet/commit/87922eda0fffdf9d5b37ce857b373cd3067ac9d2)): sc_sessionkey and secret_sc_sessionkey are now allocated with TYPE_AES_TRANSIENT_DESELECT in priority, falling back to TYPE_AES_TRANSIENT_RESET, then to persistent TYPE_AES. Previously, every secure channel initiation rewrote the key in EEPROM, wearing out the flash over the card's lifetime. Transient keys are also automatically cleared on deselect/reset, which is better hygiene for session keys. This addresses a long-standing "todo: make transient?" comment in the code.

* Use transient (RAM) EC keys for the derived keys (**behaviour change**): `bip32_extendedkey` and `taproot_tweakedkey` are now allocated with TYPE_EC_FP_PRIVATE_TRANSIENT_DESELECT in priority, falling back to TYPE_EC_FP_PRIVATE_TRANSIENT_RESET, then to persistent TYPE_EC_FP_PRIVATE (same pattern as the secure channel session keys). Previously, every derivation and every taproot tweak rewrote a key in EEPROM, including derivations made only to export a public key (xpub, master fingerprint), and the last derived private key stayed in flash after the session. A transient key loses its curve parameters along with its value, so they are set again before each derivation or tweak.
  * Clients must derive the key, and tweak it for Schnorr signatures, in the same session as the signature. After a deselect or a card reset, signing with P1=0xFF (SignTransactionHash, Musig2GenerateNonce, Musig2SignHash), tweaking it, or signing with SignSchnorrHash returns SW_INCORRECT_INITIALIZATION (0x9C13), the error already returned when no key has been derived yet. Signing with a key left over from an earlier session is no longer possible.
  * Clients that derive just before signing are not affected: Electrum-Satochip, Sparrow and Bitcoin Keeper (satochip-react-native) all do. pysatochip and Satochip-Java silently reopen the secure channel and re-verify the cached PIN when the card was reset or deselected, then resend the command: a signature resent this way after a derivation in the previous session now fails with 0x9C13 instead of using the old key.
  * For MuSig2, the encrypted secnonce still survives across sessions, but the BIP32 key must be derived again before Musig2SignHash with P1=0xFF.

* Secure channel state without EEPROM writes: the persistent `initialized_secure_channel` flag is removed, and the channel is now open if and only if the session key is loaded. The flag was written in EEPROM on every SELECT and twice per INIT_SECURE_CHANNEL (about 3 writes per NFC session); closing the channel now clears the transient session key, a RAM write. The previous session key is also erased as soon as the channel closes (SELECT, new INIT, IV counter exhaustion, factory reset), instead of staying loaded until deselect (or across deselects with TYPE_AES_TRANSIENT_RESET, or across power cycles with the persistent fallback key). An INIT_SECURE_CHANNEL that fails after loading the key clears it, so a failed INIT never leaves a channel open.

* Lighter RSA setup for the Biginteger multiplication trick: the RSA engine is only used to square numbers (exponent 2, results below the modulus), so `Biginteger.init()` no longer generates a 768-bit RSA-CRT key pair at install just to obtain a modulus. A public key with a constant 768-bit RSA modulus (generated offline, private key discarded; its factors play no role) is used instead, which saves the key generation time at install and the storage of an unused private key. The start-up self-test now checks that the engine computes 3^2 = 9, instead of only checking that it does not throw: an engine that does not compute a plain square disables the trick, rather than silently producing invalid Schnorr/MuSig2 signatures.

* Secp256k1.isOnCurve() computes x^2 and y^2 with one RSA operation each (new Biginteger.square_rsa()) instead of three, saving 4 of the 9 RSA operations of each secure channel initiation.

* HmacSha160 fills and copies its scratch buffer with Util.arrayFillNonAtomic()/arrayCopyNonAtomic() instead of byte loops, like HmacSha512 (it runs twice for every secure channel command).

### Refactoring and code cleanup

* Refactor reset to factory to v3: reset to factory is now triggered by sending one single APDU command (INS 0xFD, P1=0xAA, P2=0x55). Note that the new reset path goes through the secure channel, so INIT_SECURE_CHANNEL must be performed first. The reset deliberately requires neither a validated PIN nor a blocked PUK: anyone holding the card can block the PIN and the PUK before resetting it, so such a check would add no real security.

* Simplify PIN management (based on the same refactoring in Seedkeeper-Applet, commit [6a46bf4](https://github.com/Toporin/Seedkeeper-Applet/commit/6a46bf42acd8b25d1464115ef4bb85c041f94f3b)): the applet now uses a single PIN and a single PUK. The pins[]/ublk_pins[] arrays are replaced by single pin/puk objects (pins[0] -> pin, ublk_pins[0] -> puk). The CreatePIN (0x40) and ListPINs (0x48) commands are removed and return SW_INS_DEPRECATED when invoked. In setup(), the pin1/ublk1 fields are now ignored (but still parsed for backward compatibility with the APDU format). In VerifyPIN, ChangePIN and UnblockPIN, the P1 parameter must now be 0x00 (previously the PIN number 0x00-0x07). In GetStatus(), the two bytes reporting pin1/ublk1 tries are now always 0. The MAX_NUM_PINS constant was removed.

* Refactor getBIP32ExtendedKey() (ported from Seedkeeper-Applet commit [1efa05a](https://github.com/Toporin/Seedkeeper-Applet/commit/1efa05a13a3c21662f5db43fc7ce81ee0f1e69a9)): extended keys are now derived on the spot from the master key and master chaincode, instead of caching intermediate extended keys in the BIP32 object store (Bip32ObjectManager). The command APDU and the response format are unchanged, so client parsing is unaffected. The p2 option flags are now deprecated and silently ignored. Note the performance trade-off: on the one hand a depth-d derivation now costs d EC multiplications + 2d HMAC-SHA512 on every call (previously ~1 EC multiplication on cache hits). On the other hand, no caching operations are needed anymore. All in all, tests did not show any significant performance changes.

* Extract the keyslot selection/validation code (previously copy-pasted in 8 functions) into a new getInitializedECKey() helper: it returns the ECPrivateKey stored in a keyslot after checking that the key is initialized and has the expected type and size (secp256k1), and that its curve parameters are intact (see *Hardening*). Used in getPublicKeyFromPrivate, signMessage, SignTransaction, SignTransactionHash, TaprootTweakPrivateKey, Musig2GenerateNonce, Musig2SignHash and ResetKey (which now also gets the type/size checks for consistency). It uses tmpBuffer as scratch (recvBuffer cannot be used, as signMessage() signs data stored there).

* Add getUninitializedKey() helper for ImportKey(), which requires the opposite check (the keyslot must NOT be initialized): it returns an uninitialized ECPrivateKey slot for import, creating the key object if the slot is empty and (re)setting the secp256k1 curve parameters in all cases (which fixes re-import after a factory reset, see *Bug fixes*). The old getKey() helper (only used by ImportKey) was removed. Note: importing into an already initialized slot now returns SW_ECKEYS_INITIALIZED_KEY (0x9C1A, more specific) instead of SW_INCORRECT_P1 (0x9C10).

* Rename the main applet class from `CardEdge` to `Satochip` (`CardEdge.java` -> `Satochip.java`). The old name came from the MUSCLE CardEdge applet this code was derived from in 2015 and no longer described the class; the sibling projects already follow this convention (`SeedKeeper`, `Satodime`, `Satocash`). **No impact on clients or on installed cards:** the applet AID (`5361746F4368697000`), the package AID, the CLA byte and the whole APDU protocol are unchanged, and applets are selected by AID, so the class name never reaches the wire. The MUSCLE attribution header and the `CardEdge_CLA` constant keep the old name on purpose, the latter because it is shared with the other applets and with pysatochip's `JCconstants`.

* Code cleanup (no functional change):
  * New getPublicKey() and appendAuthentikeySignature() helpers replace 14 copies of the public key computation and 6 copies of the authentikey signature; importBIP32Seed() reuses the authentikey response code (now getAuthentikey()).
  * Removed dead code and constants: the `eckeys_flag` field (written on every key import/reset, never read), Biginteger.shrink() and the mod() loop counters, SW_DEBUG_FLAG, the unused constants of Secp256k1, and the local redefinitions of ALG_ECDSA_SHA_256, LENGTH_EC_FP_256 and TYPE_AES_TRANSIENT_* (available in the 3.0.4 API); removed unused imports.
  * Removed a redundant `taproot_tweakedkey.clearKey()` after resetSeed() in resetToFactory(), which also erased the curve parameters that resetSeed() had just restored.
  * Biginteger: the scratch buffers and FLAG_FAST_MULT_VIA_RSA are now package-private, and the RSA key, cipher and exponent constant private (they were public mutable statics). Removed the unused carry results and stale TODOs of mult_rsa_trick(), whose documentation now describes the actual method.
  * Satochip: removed the dead `puk == null` check of UnblockPIN() (setup is done, so the PUK exists); simplified the resetBIP32Seed() 2FA offset and the GetStatus() boolean flags; the BIP340/TapTweak and MuSig2 tag constants are now private.
  * SecureChannel: the response is copied to the scratch buffer non-atomically, and a redundant length check is removed. The IV counter update stays atomic on purpose (sc_buffer falls back to EEPROM on cards without enough transient memory).
  * Removed ~25 redundant casts (on variables and constants already of the target type) that generated compiler warnings during the build.

### Documentation

* SignTransactionHash() documents that the returned DER signature is not normalized to low-S: the client must replace s with n-s when s > n/2 (BIP62/BIP146), or Bitcoin nodes will reject it.
* The per-operation 2FA codes (the 32-byte value and padding constant HMAC'd for each 2FA-protected operation) are documented in the code.
* The code documents that the personalization PKI data (authentikey, certificate, personalizationDone flag) deliberately survives a factory reset.
* Biginteger.lessThan() and equalZero() are documented as not constant time, for public data only, with lessThanCT() and isZeroCT() to be used on secrets.

### Build, tests and tooling

* Add a JUnit test suite for the applet (`src/test/java/org/satochip/applet/`), run with `./gradlew test`. The tests drive the applet purely over APDUs, so the same suite runs against a real card (the default target) or against the [JCardEngine](https://github.com/martinpaljak/JCardEngine) simulator with no hardware (`-Porg.satochip.test.target=simulator`, which is what the new GitHub Actions workflow uses). Coverage focuses on the security boundaries first: the secure channel is mandatory and replay-protected, PIN/PUK try counters, the new UnblockPIN data format, setup-runs-once, feature policies (a disabled feature rejects its command and can be re-enabled), and the removed commands reporting SW_INS_DEPRECATED. On the crypto side, BIP32 derivation is checked against the specification's test vectors and cross-checked with bitcoinj, ECDSA signatures are verified with BouncyCastle, and BIP340 Schnorr signatures are verified against a verifier written out from the specification — including a regression test for the tweaked private key not surviving the first signature. The NDEF applet is covered too, including that a record written with SET_NDEF is served over the Type 4 interface. The simulator is compiled for Java 17 (see the JDK 17 build below). No applet code was changed.

* Build the applet with JDK 17 (or newer) throughout, on Gradle 8.10. Previously the build needed two JDKs: 11 to compile and convert the applet, 17 to run the test suite. The CAP still targets **JavaCard 3.0.4 with v1.5 API imports**, so card compatibility is unchanged — the build now runs the JavaCard v25.0 converter with `targetsdk = "3.0.4"` instead of the 3.0.4 SDK, which is what lifts the JDK 11 limit. Verified on a physical v0.16 card: the CAP installs over SCP02 and all 19 tests pass. The `com.fidesmo:gradle-javacard` plugin (2017, unmaintained, served over plain HTTP from a host not mirrored on Maven Central) is gone; `build.gradle` drives ant-javacard directly through Gradle's Ant integration. The legacy Ant build was removed with it, since it was the same tool behind a second config file and only ever produced the main applet; `./gradlew convertJavacard` is now the single way to build a CAP, and it contains both `Satochip` and `NDEFApplet`. Only the JavaCard 3.0.4 target is built: a 3.0.5-targeted CAP has byte-identical bytecode and differs only by declaring a higher minimum API, so it would load on strictly fewer cards for no gain. No applet source was changed.

* Always re-run the test suite against a physical card. `install` declares no outputs so it runs on every invocation, but `test` was incrementally skippable, so a second `./gradlew test` would reflash the card and then report `BUILD SUCCESSFUL` without executing a single test. The card is an input Gradle cannot see, so the card target now sets `outputs.upToDateWhen { false }`. The simulator target stays incremental, where its inputs really are fully declared.

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
