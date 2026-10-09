# AGENTS.md

Guidance for AI coding agents working on the SatoChipApplet repository.

## Project overview

SatoChipApplet is an open-source **JavaCard applet** implementing a **Bitcoin hardware wallet** with full BIP32 (hierarchical deterministic) support. "SatoChip" stands for Secure Anonymous Trustless and Open Chip. The applet runs on a smartcard (e.g. Yubikey Neo dev cards, NXP JCOP J2D081, J3D081 JCOP v2.4.2); a BIP32 seed is imported once, private keys are derived on demand and **never leave the chip** — only signatures come out. The last derived key is kept in RAM until the end of the session (cleared on deselect).

Upstream repository: https://github.com/Toporin/SatochipApplet

Main features (see `CHANGELOG.md` for the full history):

- BIP32 seed import and on-card key derivation, plus import of up to 16 plain (non-BIP32) EC keys.
- Bitcoin transaction parsing/signing (legacy + SegWit), message signing, `SignTransactionHash`.
- BIP340 Schnorr signatures and Taproot key tweaking (ins 0x7B/0x7C).
- MuSig2 partial support (BIP327 `NonceGen`/`Sign`, experimental since v0.15) with encrypted-secnonce export and nonce-reuse protection.
- Liquid-Bitcoin support (SLIP-0077 master blinding key export, ins 0x7D).
- PIN/PUK access control, optional 2FA (HMAC-SHA1 challenge via an external device), mandatory secure channel, SeedKeeper secure seed import, personalization PKI, NFC policy and feature policy (features can be enabled/disabled/blocked).
- Reset to factory settings.

**Versioning** (`CHANGELOG.md`, constants in `Satochip.java`): full versions are `vX.Y-Z.W` where `X.Y` is the PROTOCOL VERSION (client-compatibility impacting) and `Z.W` the applet version (no client impact). Current version: **0.16-0.0** (work in progress).

## Repository layout

```
build.gradle              Gradle build (canonical): CAP, install, lock, test
buildSrc/                 InstallTask / LockTask (GlobalPlatform over SCP02)
lib/ant-javacard.jar      ant-javacard Ant task (github.com/martinpaljak/ant-javacard)
sdks/                     Git submodule: Oracle JavaCard SDKs (2.1.1 .. 3.2.0)
src/main/java/org/satochip/applet/   Applet sources (Satochip, NDEFApplet, SharedMemory, helpers)
src/test/java/org/satochip/applet/   JUnit 5 APDU test suite
.github/workflows/        CI: builds the CAP and runs the suite on the simulator
gp.jar, gp.exe            Vendored GlobalPlatformPro for loading CAPs onto cards
SatoChip-v*.cap           Pre-built CAP artifacts in the worktree (untracked, ignored)
.classpath, .project      Eclipse project files (JCDK 2.2.2 + eclipse-jcde plugin)
.idea/                    Minimal IntelliJ config
```

### Source files (`src/main/java/org/satochip/applet/`)

- `Satochip.java` (~3700 lines) — the main applet class (`extends javacard.framework.Applet`). Contains the APDU dispatcher (`process()`), all instruction handlers, PIN management, 2FA, BIP32 derivation, Schnorr/Taproot, MuSig2, feature/NFC policies, PKI personalization. Derived from the MUSCLE framework, whose `CardEdge` applet gave the class its former name; the MUSCLE attribution header and the `CardEdge_CLA` constant keep that name deliberately.
- `NDEFApplet.java` — second applet in the package, installed under the NFC Forum Type 4 AID `D2760000850101`; serves a single NDEF record so tapping the card opens a link.
- `SecureChannel.java` — the mandatory secure channel (ECDH key exchange, AES-CBC + HMAC-SHA1 command/response wrapping, IV counter). Owns only its session state; the cipher, scratch EC key, crypto engines and working buffers are shared with `Satochip` and passed to its constructor, so it costs no extra RAM. Keep it that way: on many cards each `Cipher`/`Signature`/`KeyAgreement` instance reserves RAM.
- `SharedMemory.java` — the 223-byte NDEF record buffer, shared between the two applet instances.
- `Secp256k1.java` — secp256k1 domain parameters, EC key initialization helpers and on-curve validation.
- `Biginteger.java` — big-integer arithmetic on byte arrays (based on the OV-chip 2.0 project, Radboud University), optionally accelerated via the card's RSA engine (`mult_rsa_trick`).
- `HmacSha512.java`, `HmacSha160.java` — minimal HMAC implementations on top of `javacard.security.MessageDigest`.

`Transaction.java` and `Bip32ObjectManager.java` were removed in v0.16 along with the ParseTransaction/SignTransaction commands and the BIP32 cache.

## Technology stack and build

- **Language**: JavaCard — a strict subset of Java (no `int`/`long` arithmetic assumed, no garbage collection guarantees, no recursion in practice, `short` everywhere). Target API: JavaCard Classic 3.0.4 (constants added in later versions, such as `ALG_EC_SVDP_DH_PLAIN_XY` from 3.0.5, are redefined locally in `Satochip.java`).
- **Build tool**: Gradle 8.10 (wrapper included). There is no JavaCard Gradle plugin: `build.gradle` drives [ant-javacard](https://github.com/martinpaljak/ant-javacard) through Gradle's Ant integration, resolving it as `com.github.martinpaljak:ant-javacard` from `mvn.javacard.pro`. The legacy Ant build was removed; `./gradlew convertJavacard` is the only way to produce a CAP.
- **SDKs**: `sdks/` is a git submodule (https://github.com/martinpaljak/oracle_javacard_sdks). After cloning: `git submodule update --init --recursive`.

### Java versions and the JavaCard toolchain (this trips people up)

- **JDK 17 or newer for everything** — build, install and test. 17 is the floor because JCardEngine
  (the test simulator) is Java 17 bytecode; the build enforces it and fails with an explanation.
- `sourceCompatibility = 7` is a **converter requirement**, not a style choice: the converter caps
  at class file 51. Java 7 *language* features are still unusable on a card — switch-on-String
  needs `String.hashCode`, try-with-resources needs `AutoCloseable`, and neither exists in the
  JavaCard runtime. The old `1.6` setting used to rule them out by accident.
- The CAP targets **JavaCard 3.0.4** while being built by the **v25.0** SDK: `jckit =
  sdks/jc320v25.0_kit` with `targetsdk = "3.0.4"`. That kit carries the 3.0.4 API and its export
  files internally. This exact pairing matters — the 3.0.4 kit is refused on JDK 17 ("converter
  caps at 1.6"), and pointing `targetsdk` at the `jc304_kit` *directory* instead converts but then
  fails verification. **Re-verify on a real card before changing the kit, `targetsdk` or the
  ant-javacard version.** CI asserts the CAP still reports JavaCard 3.0.4 with v1.5 imports.
- The Gradle **configuration cache is unsupported**: `convertJavacard` calls `Project.ant` at
  execution time, and `InstallTask`/`LockTask` call `getProject()`. Do not enable it.

### Build commands

```sh
./gradlew convertJavacard   # -> build/javacard/org/satochip/applet/javacard/applet.cap
./gradlew install           # load + install both applets over SCP02
./gradlew test              # default target 'card'; -Porg.satochip.test.target=simulator for CI
```

Build identifiers:

- Package AID: `5361746F43686970` ("SatoChip" in ASCII)
- Applet AID: `5361746F4368697000`, main class `org.satochip.applet.Satochip`
- NDEF applet AID: `5361746F4368697001`, instance AID `D2760000850101`

### Deployment (loading onto a card)

GlobalPlatformPro is vendored in the repo root (`gp.jar` / `gp.exe`):

```sh
gp -l                                   # list applets on the card
gp -install SatoChip-3.0.4.cap          # load the applet
gp -uninstall SatoChip-3.0.4.cap        # remove it
```

## Testing

- `src/test/java/org/satochip/applet/` holds a JUnit 5 suite that drives the applet over APDUs. It runs against the JCardEngine simulator (`-Porg.satochip.test.target=simulator`, no hardware, what CI uses) or a real card (the default). See the README's Test section.
- The suite uses a **shared card**: it is set up once and reused, so every test must restore the baseline it found (PIN `1234`, all feature policies enabled). Never set a policy to BLOCKED or block the PUK in a test — those are irreversible without a factory reset.
- Negative tests must go through `TestSatochipCommandSet.sendRawSecure`/`sendRawPlain`, never `cardTransmit`: the production `cardTransmit` silently reopens the secure channel and re-verifies the PIN on 0x9C06, which turns an authorization failure into a success.
- A simulator is not a card. Green tests do not prove hardware behaviour: timing, transient-memory limits and EEPROM tearing all differ. Keep running the card target and the pysatochip hardware tests before a release.
- `./gradlew benchmarkCard` (tag `benchmark`, excluded from `test`) times Schnorr/MuSig2 and control commands on the applet already on the card, without installing; `scripts/benchmark-commits.sh BASE TARGET` builds both CAPs in temporary worktrees, installs and benchmarks each, and compares. Installs wipe the card: never run it on a card holding real funds.
- Complementary client-side coverage lives in [pysatochip](https://github.com/Toporin/pysatochip).
- `./gradlew convertJavacard` is the minimum check for any change; `./gradlew test -Porg.satochip.test.target=simulator` is the next one.

## Runtime architecture

- All communication is via **APDUs** with CLA byte `0xB0` (the NDEF applet uses CLA `0x00`). Instruction (INS) codes and status words (SW) are declared as constants at the top of `Satochip.java` — extend these lists when adding commands.
- **Secure channel is mandatory** (`needs_secure_channel = true`): in plaintext only `GET_STATUS` (0x3C), `INIT_SECURE_CHANNEL` (0x81) and `PROCESS_SECURE_CHANNEL` (0x82) are accepted; everything else must be wrapped through the secure channel or the card throws `SW_SECURE_CHANNEL_REQUIRED`.
- Setup flow: before `INS_SETUP` completes, only personalization-PKI commands are allowed; `INS_SETUP` can run only once (unless factory reset).
- Sensitive operations require prior PIN verification; several additionally require 2FA HMAC when a 2FA key is configured.
- Memory is extremely constrained: fixed-size buffers (`EXT_APDU_BUFFER_SIZE` 268, `TMP_BUFFER_SIZE` 256), transient arrays via `JCSystem.makeTransient*Array`, and a fixed-array BIP32 cache. Avoid new persistent allocations casually.
- Client software: the reference client is the Electrum-Satochip fork (https://github.com/Toporin/electrum); `SatoChipClient` is deprecated.

## Code style guidelines

- Match the existing style of `Satochip.java`: 4-space indentation, `private final static` constants in UPPER_SNAKE_CASE, handlers named after their function (`GetStatus`, `ImportKey`, `SignTransactionHash`...), cast numeric literals to `(byte)`/`(short)` explicitly.
- JavaCard subset only: no `int` literals beyond `short` range without care, no `long`, no floating point, no exceptions other than `ISOException`/`CryptoException`-style patterns already used, beware of transient vs persistent memory.
- Every source file carries a license header; keep headers intact and note provenance for third-party-derived code (MUSCLE, BTChip, OV-chip).
- When bumping versions, update `PROTOCOL_*_VERSION`/`APPLET_*_VERSION` in `Satochip.java`, the version-history comment block above them, and `CHANGELOG.md` together.

## Security considerations

This is a wallet holding real private keys — treat changes accordingly:

- Private keys and seeds must **never** be exportable; signatures are the only output of key material. Preserve this invariant.
- PIN-gating, 2FA checks and the mandatory secure channel are security boundaries — do not weaken or bypass them (including "temporarily" in debug code; see git history for reverted hardcoded-key debug commits).
- Do not introduce hardcoded keys, seeds, nonces or randomness. Use `javacard.security.RandomData`.
- MuSig2 secnonces are exportable only in encrypted form and are single-use (counter + id-list mechanism); any change there must preserve nonce-reuse protection.
- The software HMAC-SHA512 implementation may be susceptible to side-channel attacks against attackers with physical access — a known, documented limitation.
- Feature policy: optional features (Schnorr, Nostr signing, Liquid blinding key export, MuSig2) can be disabled or permanently blocked; respect the policy checks.
- The project is AGPL v3 overall; some files carry LGPL 2.1 (MUSCLE-derived) or GPL v2 (OV-chip-derived) headers — keep license combinations intact.
