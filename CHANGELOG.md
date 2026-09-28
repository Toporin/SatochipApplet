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

* Harden importEncryptedSecret() input validation: the encrypted_secret_size field is now checked to be positive and a multiple of the AES block size (16 bytes) before use (previously a value with the high bit set was read as a negative short, slipped past the length check, and caused negative-length exceptions). The PKCS#7 padding length read from the decrypted data is now also validated to be in range [1, 16] and not larger than the decrypted size, returning SW_INVALID_PARAMETER otherwise.

* Merge [PR #22](https://github.com/Toporin/SatochipApplet/pull/22) (thanks @kkdao): count the two-byte size prefix in importTrustedPubkey() (fixes [#21](https://github.com/Toporin/SatochipApplet/issues/21)). The length check compared Lc with pubkey_size alone, so a command with Lc = 65 or 66 passed and the 65-byte copy read past the command data, silently storing a corrupted trusted pubkey. Well-formed 67-byte commands behave exactly as before.

* Refactor reset to factory to v3: Reset to factory is now triggered by sending one single APDU command. Note that the new reset path goes through the secure channel, so INIT_SECURE_CHANNEL must be performed first. resetToFactory() now also resets and unblocks all PINs and PUKs, restoring their try counters (OwnerPIN.update() does not reset them).

* Extend UnblockPIN(): a forgotten PIN can now be unblocked AND changed by providing the PUK code. The data format is now [PUK_size(1b) | PUK | (optional) PIN_size(1b) | (optional) PIN]: if a new PIN is provided, it replaces the forgotten one; if only the PUK is provided, the PIN is simply unblocked with its previous value. After a successful unblock, the PIN and PUK try counters are restored. All inputs are validated before any state change and the PUK is checked with its exact length. Compatibility note: the previous format ([PUK] without size prefix) is not accepted anymore, clients must be updated.

* Improve authentikey management (ported from Seedkeeper-Applet commit [29ce8f0](https://github.com/Toporin/Seedkeeper-Applet/commit/29ce8f0984dd6ae02e0689ccf339f3b2865bc543)): the InitiateSecureChannel() response now also returns the authentikey coordx ([coordx_size(2b) | authentikey_coordx] appended), allowing non-ambiguous recovery of the authentikey public key from the signature. The PIN requirement is removed from getAuthentikey() (ins 0xAD) and export_PKI_pubkey() (ins 0x98), since the authentikey public key is public data that can already be recovered from the secure channel initiation. getBIP32AuthentiKey() (ins 0x73) is now documented as deprecated (kept for backward compatibility).

* Use transient (RAM) AES session keys for the secure channels (ported from Seedkeeper-Applet commit [87922ed](https://github.com/Toporin/Seedkeeper-Applet/commit/87922eda0fffdf9d5b37ce857b373cd3067ac9d2)): sc_sessionkey and secret_sc_sessionkey are now allocated with TYPE_AES_TRANSIENT_DESELECT in priority, falling back to TYPE_AES_TRANSIENT_RESET, then to persistent TYPE_AES. Previously, every secure channel initiation rewrote the key in EEPROM, wearing out the flash over the card's lifetime. Transient keys are also automatically cleared on deselect/reset, which is better hygiene for session keys. This addresses a long-standing "todo: make transient?" comment in the code.

* Simplify SignSchnorrHash(): the R = rand*G computation now uses the ephemeral_privkey scratch EC key (already used the same way in InitiateSecureChannel, ImportKey and Musig2GenerateNonce) instead of borrowing the taproot_tweakedkey object and restoring it afterwards. The tweaked private key is therefore never overwritten, making the bug fixed in b1fb9dd (borrowed key not restored) structurally impossible. No functional change: the signature output is identical.

* Return card status on card select (ported from Seedkeeper-Applet commit [01bc193](https://github.com/Toporin/Seedkeeper-Applet/commit/01bc19376fdc2dd22de4a265ddacb401a709f98f)): the SELECT APDU response now includes the same data as a GET_STATUS command (applet version, PIN/PUK tries remaining, 2FA/seeded/setup flags, NFC & feature policies), saving a round trip for clients. GetStatus() no longer checks P1/P2, since the SELECT command carries its own parameters (P1=0x04). This information was already available to anyone through the unauthenticated GET_STATUS command, so nothing new is disclosed.

* Refactor getBIP32ExtendedKey() (ported from Seedkeeper-Applet commit [1efa05a](https://github.com/Toporin/Seedkeeper-Applet/commit/1efa05a13a3c21662f5db43fc7ce81ee0f1e69a9)): extended keys are now derived on the spot from the master key and master chaincode, instead of caching intermediate extended keys in the BIP32 object store (Bip32ObjectManager). The command APDU and the response format are unchanged, so client parsing is unaffected. The p2 option flags (0x80 reset cache, 0x40 optimize non-hardened derivation, 0x20 store key as object) are now deprecated and silently ignored. Note the performance trade-off: on the one hand a depth-d derivation now costs d EC multiplications + 2d HMAC-SHA512 on every call (previously ~1 EC multiplication on cache hits). On the other hand, no caching operations are needed anymore. All in all, tests did not show any significant performance changes.

* Extract the keyslot selection/validation code (previously copy-pasted in 8 functions) into a new getInitializedECKey() helper: it returns the ECPrivateKey stored in a keyslot after checking that the key is initialized and has the expected type and size (secp256k1). Used in getPublicKeyFromPrivate, signMessage, SignTransaction, SignTransactionHash, TaprootTweakPrivateKey, Musig2GenerateNonce, Musig2SignHash and ResetKey (which now also gets the type/size checks for consistency). ImportKey() uses a separate helper (see below) since it requires the opposite check (the keyslot must NOT be initialized). The curve parameters integrity check (countermeasure against fault injection / curve substitution), previously applied only in getPublicKeyFromPrivate(), is now also part of the helper, so all keyslot users benefit from it; it uses tmpBuffer as scratch (recvBuffer cannot be used, as signMessage() signs data stored there). No functional change.

* Add getUninitializedKey() helper for ImportKey(): it returns an uninitialized ECPrivateKey slot for import, creating the key object if the slot is empty and (re)setting the secp256k1 curve parameters in all cases. This also fixes re-import after a factory reset: clearKey() clears the curve parameters, so slots that previously held a key lost them and would have failed import. The old getKey() helper (only used by ImportKey) was removed. Note: importing into an already initialized slot now returns SW_ECKEYS_INITIALIZED_KEY (0x9C1A, more specific) instead of SW_INCORRECT_P1 (0x9C10).

* Remove the ParseTransaction (0x71) and SignTransaction (0x6F) commands: they are deprecated and now return SW_INS_DEPRECATED (0x9C26) when invoked. Clients should use SignTransactionHash (0x7A) to sign transaction hashes (the client computes the sighash itself) and perform any transaction parsing off-card. Related code and objects are also removed: the Transaction.java parser class, the transactionData state (cached tx hash and cumulative amount for the 2FA limit), the PARSE_STD/PARSE_SEGWIT constants, the SW_INCORRECT_TXHASH status word, the "Tx approval" 2FA code entry, and the now-unused Biginteger methods swap/getLSB/subtract1_carry. The 2FA amount_limit field is still accepted in setup for protocol compatibility but is now deprecated and unused.

* Remove the signMessage (0x6E) command: it is deprecated and now returns SW_INS_DEPRECATED (0x9C26) when invoked. Clients should use SignTransactionHash (0x7A) to sign the (double-hashed) message hash instead, computing the message hash off-card. Related code and objects are also removed: the signMessage() function, the BITCOIN_SIGNED_MESSAGE_HEADER constant, the sign_flag multi-chunk state, the "Msg signing" 2FA code entry, and the Biginteger VarInt helpers (encodeVarInt, encodeShortToVarInt, isStrictlyLessThanUnsigned) as well as the dead Shift1bit/setZero/setByte methods (the latter already unused).

* Add GET_RANDOM (0x30) command: returns 1 to 64 random bytes per call generated on-card by the platform's secure random number generator, for use as additional entropy (seeds, encryption keys, passwords, ...). The command requires PIN validation and returns the bytes through the secure channel (encrypted); random bytes are generated directly into the APDU buffer to avoid any leakage of sensitive data held in shared working buffers. The command is gated by a new FEATURE_ID_RANDOM (4) feature policy (enabled by default; can be disabled or permanently blocked with setFeaturePolicy and reset by factory reset). GetStatus() now also returns the random feature policy as an additional byte (offset 17).

* Simplify PIN management (based on the same refactoring in Seedkeeper-Applet, commit [6a46bf4](https://github.com/Toporin/Seedkeeper-Applet/commit/6a46bf42acd8b25d1464115ef4bb85c041f94f3b)): the applet now uses a single PIN and a single PUK. The pins[]/ublk_pins[] arrays are replaced by single pin/puk objects (pins[0] -> pin, ublk_pins[0] -> puk). The CreatePIN (0x40) and ListPINs (0x48) commands are removed and return SW_INS_DEPRECATED when invoked. In setup(), the pin1/ublk1 fields are now ignored (but still parsed for backward compatibility with the APDU format). In VerifyPIN, ChangePIN and UnblockPIN, the P1 parameter must now be 0x00 (previously the PIN number 0x00-0x07). In GetStatus(), the two bytes reporting pin1/ublk1 tries are now always 0. The MAX_NUM_PINS constant was removed.

* Remove the default PIN value: the PIN object is now null until setup() is called for the first time, where it is created (or simply updated on later setups). The default PIN field of the setup APDU is now ignored (but still parsed for backward compatibility), so setup() no longer requires knowledge of the default PIN. This eliminates a permanent brick scenario where the default PIN (only 3 tries) could be blocked before setup, making setup() impossible with no recovery path. Before setup, VerifyPIN() trivially succeeds and the personalization PKI commands skip the PIN check (pin != null guard), which is equivalent in practice to the previous public default PIN value. The PIN_INIT_VALUE constant was removed.

* Add an NDEF applet and the SET_NDEF (0x3F) command (ported from Seedkeeper-Applet): the CAP now contains a second applet, NDEFApplet, installed under the standard NFC Forum Type 4 AID D2760000850101. It serves a single NDEF record so that tapping the card on a phone opens a link, without any app installed. The default record is a universal link to https://satochip.io/quick-start/satochip/ (it works on both Android and iOS). The record is stored in a 224-byte buffer shared between the two applet instances (SharedMemory) and can be replaced either at install time through the NDEF applet install parameters, or at any time afterwards with the new SET_NDEF (0x3F) command (p2=0x00 to set, p2=0x01 to get). Like every other command, SET_NDEF requires the secure channel, a completed setup and a validated PIN. This is backward compatible: the protocol version stays 0.16 and clients that do not know the new command are unaffected.

* Add a JUnit test suite for the applet (`src/test/java/org/satochip/applet/`), run with `./gradlew test`. The tests drive the applet purely over APDUs, so the same suite runs against a real card (the default target) or against the [JCardEngine](https://github.com/martinpaljak/JCardEngine) simulator with no hardware (`-Porg.satochip.test.target=simulator`, which is what the new GitHub Actions workflow uses). Coverage focuses on the security boundaries first: the secure channel is mandatory and replay-protected, PIN/PUK try counters, the new UnblockPIN data format, setup-runs-once, feature policies (a disabled feature rejects its command and can be re-enabled), and the removed commands reporting SW_INS_DEPRECATED. On the crypto side, BIP32 derivation is checked against the specification's test vectors and cross-checked with bitcoinj, ECDSA signatures are verified with BouncyCastle, and BIP340 Schnorr signatures are verified against a verifier written out from the specification — including a regression test for the tweaked private key not surviving the first signature. The NDEF applet is covered too, including that a record written with SET_NDEF is served over the Type 4 interface. Note the suite needs a JDK 17 alongside the JDK 11 used to build the applet (`JAVA17_HOME`), since the simulator is compiled for Java 17. No applet code was changed.

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
