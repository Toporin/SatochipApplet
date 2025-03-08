# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

Satochip applet full versions follows this format: vX.Y-Z.W where:
* X.Y refers to the PROTOCOL VERSION: changes that impact compatibility with the client side (e.g new functionalities, major patch...)
* Z.W refers to changes with no impact on compatibility of the client (e.g minor patches, optimizations...)

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
