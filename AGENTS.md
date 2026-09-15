# AGENTS.md

Guidance for AI coding agents working on the SatoChipApplet repository.

## Project overview

SatoChipApplet is an open-source **JavaCard applet** implementing a **Bitcoin hardware wallet** with full BIP32 (hierarchical deterministic) support. "SatoChip" stands for Secure Anonymous Trustless and Open Chip. The applet runs on a smartcard (e.g. Yubikey Neo dev cards, NXP JCOP J2D081, J3D081 JCOP v2.4.2); a BIP32 seed is imported once, private keys are derived on demand and **never leave the chip** — only signatures come out. Derived keys are cached in secure memory.

Upstream repository: https://github.com/Toporin/SatochipApplet

Main features (see `CHANGELOG.md` for the full history):

- BIP32 seed import and on-card key derivation, plus import of up to 16 plain (non-BIP32) EC keys.
- Bitcoin transaction parsing/signing (legacy + SegWit), message signing, `SignTransactionHash`.
- BIP340 Schnorr signatures and Taproot key tweaking (ins 0x7B/0x7C).
- MuSig2 partial support (BIP327 `NonceGen`/`Sign`, experimental since v0.15) with encrypted-secnonce export and nonce-reuse protection.
- Liquid-Bitcoin support (SLIP-0077 master blinding key export, ins 0x7D).
- PIN/PUK access control, optional 2FA (HMAC-SHA1 challenge via an external device), mandatory secure channel, SeedKeeper secure seed import, personalization PKI, NFC policy and feature policy (features can be enabled/disabled/blocked).
- Reset to factory settings.

**Versioning** (`CHANGELOG.md`, constants in `CardEdge.java`): full versions are `vX.Y-Z.W` where `X.Y` is the PROTOCOL VERSION (client-compatibility impacting) and `Z.W` the applet version (no client impact). Current version: **0.15-0.1**.

## Repository layout

```
build.xml                 Ant build script (the only build entry point)
lib/ant-javacard.jar      ant-javacard Ant task (github.com/martinpaljak/ant-javacard)
sdks/                     Git submodule: Oracle JavaCard SDKs (2.1.1 .. 3.2.0)
src/org/satochip/applet/  All applet sources (7 Java files, ~6k lines total)
gp.jar, gp.exe            Vendored GlobalPlatformPro for loading CAPs onto cards
SatoChip-v*.cap           Pre-built CAP artifacts in the worktree (untracked, ignored)
.classpath, .project      Eclipse project files (JCDK 2.2.2 + eclipse-jcde plugin)
.idea/                    Minimal IntelliJ config
```

There are no other config files (no Maven/Gradle, no CI, no test directory).

### Source files (`src/org/satochip/applet/`)

- `CardEdge.java` (~4300 lines) — the main and only applet class (`extends javacard.framework.Applet`). Contains the APDU dispatcher (`process()`), all instruction handlers, PIN management, secure channel, 2FA, BIP32 derivation, Schnorr/Taproot, MuSig2, feature/NFC policies, PKI personalization. Derived from the MUSCLE framework.
- `Transaction.java` — Bitcoin transaction parser (derived from Ledger's btchipJC).
- `Secp256k1.java` — secp256k1 domain parameters and EC key initialization helpers.
- `Biginteger.java` — big-integer arithmetic on byte arrays (based on the OV-chip 2.0 project, Radboud University), optionally accelerated via the card's RSA engine.
- `Bip32ObjectManager.java` — fixed-array memory manager for the BIP32 derivation cache.
- `HmacSha512.java`, `HmacSha160.java` — minimal HMAC implementations on top of `javacard.security.MessageDigest`.

## Technology stack and build

- **Language**: JavaCard — a strict subset of Java (no `int`/`long` arithmetic assumed, no garbage collection guarantees, no recursion in practice, `short` everywhere). Target API: JavaCard Classic 3.0.4 (some code paths were originally written against 2.2.2, hence local constant redefinitions in `Secp256k1.java`).
- **Build tool**: Apache Ant + the `ant-javacard` task (`lib/ant-javacard.jar`).
- **SDKs**: `sdks/` is a git submodule (https://github.com/martinpaljak/oracle_javacard_sdks). After cloning: `git submodule update --init --recursive`.

### Build command

```sh
ant build
```

`build.xml` compiles `src/org/satochip/applet` against `sdks/jc304_kit` and produces `SatoChip-3.0.4.cap` (output name is hardcoded in `build.xml`). Build identifiers:

- Package AID: `5361746F43686970` ("SatoChip" in ASCII)
- Applet AID: `5361746F4368697000`, main class `org.satochip.applet.CardEdge`

The Eclipse IDE with the eclipse-jcde plugin can also be used (see `.classpath`/`.project`), but Ant is the canonical headless path.

### Deployment (loading onto a card)

GlobalPlatformPro is vendored in the repo root (`gp.jar` / `gp.exe`):

```sh
gp -l                                   # list applets on the card
gp -install SatoChip-3.0.4.cap          # load the applet
gp -uninstall SatoChip-3.0.4.cap        # remove it
```

## Testing

- There is **no automated test suite in this repository** (the README's mention of a "test package run during build" is outdated — `build.xml` has no test target).
- Verification is done externally: the MuSig2 code was validated against the official BIP327 test vectors by the maintainers; functional testing happens through client software (see below). When changing crypto logic, state clearly that on-card/client-side verification is still needed — do not claim it was tested here.
- Compiling with `ant build` is the minimum check for any change.

## Runtime architecture

- All communication is via **APDUs** with CLA byte `0xB0`. Instruction (INS) codes and status words (SW) are declared as constants at the top of `CardEdge.java` — extend these lists when adding commands.
- **Secure channel is mandatory** (`needs_secure_channel = true`): in plaintext only `GET_STATUS` (0x3C), `INIT_SECURE_CHANNEL` (0x81) and `PROCESS_SECURE_CHANNEL` (0x82) are accepted; everything else must be wrapped through the secure channel or the card throws `SW_SECURE_CHANNEL_REQUIRED`.
- Setup flow: before `INS_SETUP` completes, only personalization-PKI commands are allowed; `INS_SETUP` can run only once (unless factory reset).
- Sensitive operations require prior PIN verification; several additionally require 2FA HMAC when a 2FA key is configured.
- Memory is extremely constrained: fixed-size buffers (`EXT_APDU_BUFFER_SIZE` 268, `TMP_BUFFER_SIZE` 256), transient arrays via `JCSystem.makeTransient*Array`, and a fixed-array BIP32 cache. Avoid new persistent allocations casually.
- Client software: the reference client is the Electrum-Satochip fork (https://github.com/Toporin/electrum); `SatoChipClient` is deprecated.

## Code style guidelines

- Match the existing style of `CardEdge.java`: 4-space indentation, `private final static` constants in UPPER_SNAKE_CASE, handlers named after their function (`GetStatus`, `ImportKey`, `SignTransactionHash`...), cast numeric literals to `(byte)`/`(short)` explicitly.
- JavaCard subset only: no `int` literals beyond `short` range without care, no `long`, no floating point, no exceptions other than `ISOException`/`CryptoException`-style patterns already used, beware of transient vs persistent memory.
- Every source file carries a license header; keep headers intact and note provenance for third-party-derived code (MUSCLE, BTChip, OV-chip).
- When bumping versions, update `PROTOCOL_*_VERSION`/`APPLET_*_VERSION` in `CardEdge.java`, the version-history comment block above them, and `CHANGELOG.md` together.

## Security considerations

This is a wallet holding real private keys — treat changes accordingly:

- Private keys and seeds must **never** be exportable; signatures are the only output of key material. Preserve this invariant.
- PIN-gating, 2FA checks and the mandatory secure channel are security boundaries — do not weaken or bypass them (including "temporarily" in debug code; see git history for reverted hardcoded-key debug commits).
- Do not introduce hardcoded keys, seeds, nonces or randomness. Use `javacard.security.RandomData`.
- MuSig2 secnonces are exportable only in encrypted form and are single-use (counter + id-list mechanism); any change there must preserve nonce-reuse protection.
- The software HMAC-SHA512 implementation may be susceptible to side-channel attacks against attackers with physical access — a known, documented limitation.
- Feature policy: optional features (Schnorr, Nostr signing, Liquid blinding key export, MuSig2) can be disabled or permanently blocked; respect the policy checks.
- The project is AGPL v3 overall; some files carry LGPL 2.1 (MUSCLE-derived) or GPL v2 (OV-chip-derived) headers — keep license combinations intact.
