# SatochipApplet
Open source javacard applet implementing a crypto-currency hardware wallet with full BIP32/BIP39 support.

# Demonstration 

[![demonstrationon youtube](https://i.ytimg.com/vi/dbQoUrcb8SI/hqdefault.jpg?sqp=-oaymwEcCNACELwBSFXyq4qpAw4IARUAAIhCGAFwAcABBg==&rs=AOn4CLDn6M4pa5vMLDvRTFuL00UejiWmeQ)](https://youtu.be/t0IsK1fpEQQ)

# Introduction

Satochip stands for **S**ecure **A**nonymous **T**rustless and **O**pen **Chip**. It is a javacard applet that can be used as a secure hardware wallet running for example on a [Yubikey Neo](https://store.yubico.com/store/catalog/product_info.php?ref=368&products_id=72&affiliate_banner_id=1). The Satochip applet has full BIP32/BIP39 supports.

Using Satochip, an initial BIP32 seed is imported in the javacard and private keys are derived as requested by an external application. *Private keys are never exported outside of the secure chip*. To improve performances, the result of key derivation is cached in secure memory for future requests so that a specific derivation path is only computed once.

The Satochip also supports the import of regular (non-BIP32 keys) such as vanity keys. Here again, private keys cannot be exported outside of the secure chip. Up to 16 regular keys can be imported on the chip. In any case, the private keys can be used to sign transactions and Bitcoin messages, if sufficient credentials are provided.

Access to private keys (creation, derivation and signature) is enforced through the use of PIN code (from 4 to 16 chars).

*This software is provided 'as-is', without any express or implied warranty. In no event will the authors be held liable for any damages arising from the use of this software.*

Advantages:
- Code is free and open source (no NDA required!)
- Code easy to read and maintain (java card is a subset of java)
- Multiple form factor could be supported in addition to Yubikey (e.g sim cards)
- Plug and play
- Smartcards have a long experience in dealing with security and physical security in particular
- Can be easily used or extended for other crypto-currencies
- Critical functionalities are covered by a test suite run against the card, including the official Bitcoin BIP test vectors (see [Test](#test))

Also, if used with a Yubikey:
- Yubikey has minimal size and is practically indestructible;
- The Yubico company is not going anywhere anytime soon;
- Many promising functionalities: NFC, Yubikey OTP, U2F, ...;
- Possibility to use the HMAC-SHA1 challenge-response of the Yubikey as second factor for additional security against malwares.

Disadvantages:
- Building the applet might be a bit tricky;
- The software implementation of HMAC-SHA512 could have an potential impact on the physical security against side-channel attacks (for attackers with physical access to the chip).

# Supported hardware

To support Bitcoin signatures, the javacard must support ALG_ECDSA_SHA_256, which in practice requires a javacard compliant with the JavaCard 3.0.1 specification. Note that this is a necessary but not sufficient condition since javacards typically implements only a subset of the specification.

The card must also implement `KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY`, which is part of JavaCard
3.0.5, so in practice a 3.0.5-capable card is required. This is a *runtime* requirement on the
card's implementation and is independent of the CAP, which targets JavaCard 3.0.4 so that it loads
as widely as possible — the algorithm is selected by a constant passed to a method that already
exists in 3.0.4. [Keycard](https://github.com/keycard-tech/status-keycard) documents the same
combination.
A detailed list of javacard and their supported features is available [here](http://www.fi.muni.cz/~xsvenda/jcsupport.html).

An interesting guide to consult before shopping can be found [here](https://github.com/martinpaljak/GlobalPlatformPro/tree/master/docs/JavaCardBuyersGuide).

## Tested and working

### Yubikey Neo
**Important remark:** the Yubikeys currently sold by Yubico are configured for production only and it is not possible to load the applet on these dongles (see [this link](https://www.yubico.com/2014/07/yubikey-neo-updates/) for more details). Only the development Yubikeys (with serial number below 3,000,000) are suitable for our use! 

### NXP JCOP J2D081
Available for purchase [here](https://www.javacardsdk.com/product/j2d081/). (MOQ: 5 pieces).

### Swissbit PS-100u VE card Secure micro SD memory card
More info [here](http://www.swissbit.com/index.php?option=com_content&view=article&id=293&Itemid=601)
(Note however that Swissbit does not sell its product directly to end users but only to business partners).

### J3D081 JCOP v2.4.2 R2
Available for purchase [here](https://www.motechno.com/product/j3d081-dual-interface-javacard-3-0-1/). (MOQ: 1 piece).

# Buidl

You can build the javacard CAP files or use the lastest [built version](https://github.com/Toporin/SatochipApplet/releases).

CAP files are built with Gradle, which drives the [ant-javacard](https://github.com/martinpaljak/ant-javacard) converter. See [Building using Gradle](#building-using-gradle).

## Building using Gradle

The build produces a CAP containing **both** applets of the package (`CardEdge` and
`NDEFApplet`) and can install them on a card without GlobalPlatformPro.

### Requirements

* **OpenJDK 17 or newer**, with `JAVA_HOME` pointing at it. 17 is the minimum because the test
  simulator is compiled for Java 17; there is no upper bound.
```
sudo apt install openjdk-17-jdk
export JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64
```

* The JavaCard SDKs, which come in as a git submodule. Clone with:
```
git clone --recurse-submodules https://github.com/Toporin/SatochipApplet.git
```
or, for an existing clone:
```
git submodule update --init
```

Gradle itself is downloaded by the wrapper, so nothing else has to be installed.

### Building

```
./gradlew convertJavacard
```

The CAP file is written to `build/javacard/org/satochip/applet/javacard/applet.cap`. It contains
both the `CardEdge` applet (AID `5361746F4368697000`) and the `NDEFApplet` (AID
`5361746F4368697001`). You can check its content with:

```
java -jar gp.jar --info --cap build/javacard/org/satochip/applet/javacard/applet.cap
```

When cutting a release, rename that file to the applet version, as the published artifacts are
named (for example `SatoChip-v0.16-0.0.cap`); the build itself produces only `applet.cap`.

#### Why the CAP targets 3.0.4 but is built with a newer SDK

The applet must stay loadable on JavaCard 3.0.4 cards, but the 3.0.4 SDK's converter only accepts
Java 6 class files and cannot run on a JDK newer than 11. The build therefore runs the **v25.0**
converter (`sdks/jc320v25.0_kit`) with **`targetsdk = "3.0.4"`**, which emits a CAP declaring
JavaCard 3.0.4 with `v1.5` API imports — the same thing the old JDK 11 build produced. That kit
ships the 3.0.4 API and its export files internally, which is why it can target 3.0.4 on its own.
The pairing is specific: pointing `targetsdk` at the `jc304_kit` *directory* instead fails
verification, and the 3.0.4 kit itself is refused on JDK 17. Re-verify against a card before
changing it.

### Installing on a card

```
./gradlew install
```

This loads the package and installs both applet instances over a GlobalPlatform SCP02 secure
channel. It requires a card that:

* uses the T=1 protocol and SCP02, and
* still has either the GlobalPlatform default key `404142434445464748494a4b4c4d4e4f` or the Keycard
  development key `c212e073ff8b4bbfaff4de8ab655221f`.

The card keys are never rewritten by this task. If your card uses different keys, use
[GlobalPlatformPro](https://github.com/martinpaljak/GlobalPlatformPro) (`gp.jar`) instead.

Keep **only one reader connected**: the task picks the first reader that has a card in it.

### Optional local settings

`gradle.properties` is deliberately *not* committed (the SDK path is set in `build.gradle`), so you
can use it for local-only settings. On a slow network, or if the build fails with
`Java heap space`, you may want:

```
systemProp.org.gradle.internal.http.connectionTimeout=180000
systemProp.org.gradle.internal.http.socketTimeout=180000
org.gradle.jvmargs=-Xmx2g
```

## NDEF tag

The package contains a small second applet, `NDEFApplet`, installed under the standard NFC Forum
Type 4 tag AID `D2760000850101`. It serves a single NDEF record, so that tapping the card on a
phone opens a link even if no app is installed.

The default record is a universal link to <https://satochip.io/quick-start/satochip/>, which works
on both Android and iOS.

The record can be changed in two ways:

* **at install time**, through the NDEF applet's install parameters (see `NDEF_TAG` in
  `buildSrc/src/main/java/org/satochip/build/InstallTask.java`, empty by default, which keeps the
  record compiled into `SharedMemory.java`);
* **at any time afterwards**, with the `SET_NDEF` command (`INS 0x3F`, `P2=0x00` to set, `P2=0x01`
  to get). Like every other Satochip command, it requires the secure channel, a completed setup and
  a validated PIN.

The record is at most 224 bytes and is stored as `[size (1b) | NLEN (2b) | NDEF record]`.

## Locking a card (DESTRUCTIVE)

> :warning: **`./gradlew lock` is irreversible. Read this before running it.**
>
> The task replaces the card's GlobalPlatform keys with **random keys that are never displayed nor
> saved anywhere**, and then moves the card to the `SECURED` state.
>
> Afterwards **nobody — including you, the card owner — can delete, update or reinstall the applet,
> or load any other applet on that card. There is no way to undo this.**
>
> Data stored in the applet is *not* affected, and the applet-level factory reset
> (`INS_RESET_TO_FACTORY`) keeps working, so the card remains fully usable as a Satochip.
>
> This is intended only for production cards, after all testing is finished. Never run it on a
> development card.

Because of this, the task refuses to run unless you confirm explicitly:

```
./gradlew lock -PconfirmLock=YES
```

# Test

The applet has a JUnit suite in `src/test/java/org/satochip/applet/`. It drives the applet purely
over APDUs, exactly as a client would, so the same tests run either against a simulator or against
a real card.

### Requirements

The same JDK 17 (or newer) as the build — nothing extra. 17 is the minimum because
[JCardEngine](https://github.com/martinpaljak/JCardEngine), the simulator, is compiled for Java 17.

### Running

```
./gradlew test
```

The default target is **`card`**: this builds the CAP, installs it on the card in the reader (so
the usual `install` requirements apply) and then runs the suite against it. As with
`./gradlew install`, keep only one reader connected.

> :warning: `./gradlew test` **reinstalls the applet**, which erases the seed, keys and PIN on the
> card in the reader. Only run it against a development card.

To run without hardware, against the simulator:

```
./gradlew test -Porg.satochip.test.target=simulator
```

This is what CI uses. Test reports land in `build/reports/tests/test/`.

### What is covered

Security boundaries first: the secure channel is mandatory and replay-protected, PIN/PUK try
counters, the v0.16 `UnblockPIN` format, setup-runs-once, feature policies (a disabled feature
rejects its command and can be re-enabled), and the removed commands reporting
`SW_INS_DEPRECATED`. Then the crypto: BIP32 derivation against the specification's test vectors
and cross-checked with bitcoinj, ECDSA signatures verified with BouncyCastle, and BIP340 Schnorr
signatures verified against a verifier written out from the specification — including a regression
test for the v0.16 bug where the tweaked private key did not survive the first signature. The NDEF
applet is covered too, including that a record written with `INS_SET_NDEF` is served over the
Type 4 interface.

The suite uses a **shared card**: it is set up once and reused, because a factory reset on applet
versions before v0.16 needed the card to be physically removed and reinserted. Every test restores
the baseline state it found, and nothing ever sets a policy to BLOCKED or blocks the PUK, since
those are irreversible without a factory reset.

Some tests are skipped rather than failed when the target lacks a capability — notably Schnorr,
which needs the card's RSA engine for `Biginteger.mult_rsa_trick()`. On the simulator that
currently requires a one-line JCardEngine patch (see `jcardengine-pr.md`); without it the Schnorr
test reports as skipped.

### Client-side tests

Complementing this, the [pysatochip](https://github.com/Toporin/pysatochip) library tests the
applet from the client side: offline tests that pin a BIP340/BIP341 reference implementation to
the official Bitcoin test vectors, and hardware tests that run BIP32 derivation, signing,
taproot/schnorr and MuSig2 against a card. See
[Running the Tests](https://github.com/Toporin/pysatochip#running-the-tests). Those hardware tests
are destructive too: development cards only.

# Install

Once you have a CAP file, you have to download it on the chip card. You can use [GlobalPlatformPro](https://github.com/martinpaljak/GlobalPlatformPro) to do this:

- Download the latest release from https://github.com/martinpaljak/GlobalPlatformPro/releases
- (Put the CAP file in the same folder as the GPJ jar file for convenience)
- To list the applets loaded on a smartcard: `gp.exe -l`
- To load the SatoChip applet: `gp.exe -install .\SatoChip-0.12-05.cap`
- To delete the SatoChip applet: `gp.exe -uninstall .\SatoChip-0.12-05.cap`
- You can also use the gp.jar library: `java -jar gp.jar -install .\SatoChip-0.12-05.cap`

A more detailed tutorial is available on the GlobalPlatformPro [repository](https://github.com/martinpaljak/GlobalPlatformPro).

# Use

To use the applet, you have to connect your client application to the smartcard and send command APDU. These commands will be processed by the smartcard who will then send a response APDU. 

### Supported software clients

- Bitcoin: the [Bitcoin Electrum-Satochip](https://github.com/Toporin/electrum-satochip/releases) is a version of [Electrum](https://github.com/spesmilo/electrum) that was slightly modified to integrate the Satochip hardware wallet.
- Litecoin: the [Litecoin Electrum-Satochip](https://github.com/Toporin/electrum-satochip/releases) is a version of [Electrum for Litecoin](https://github.com/pooler/electrum-ltc/) that was slightly modified to integrate the Satochip hardware wallet.
- Bitcoin Cash: the [Electron Cash-Satochip](https://github.com/Toporin/electrum-satochip/releases) is a version of [Electron Cash](https://github.com/Electron-Cash/Electron-Cash) that was slightly modified to integrate the Satochip hardware wallet.
**Note:** Satochip is natively supported by Electron Cash, we strongly encourage you to download the client from the [official website](https://electroncash.org/).
- eCash (XEC): Satochip is natively supported by Electrum ABC, we strongly encourage you to download the client from the [official website](https://www.bitcoinabc.org/electrum/).

- Metamask: you can use your Satochip hardware wallet with a forked version of Metamask called [Satomask](https://github.com/Toporin/metamask-extension/releases). To allow the communication between the card and your web browser, you will need the [Satochip Bridge](https://github.com/Toporin/Satochip-Bridge/releases).

- MyEtherWallet: you can use your Satochip hardware wallet with a forked version of MyEtherWallet called [MEW Satochip](https://github.com/Toporin/MyEtherWallet/releases). To allow the communication between the card and your web browser, you will need the [Satochip Bridge](https://github.com/Toporin/Satochip-Bridge/releases).

### Deprecated (use older releases for this)
[SatoChipClient](https://github.com/Toporin/SatoChipClient) is a small java library that allows to easily interface the SatoChip applet to your application through a simple set of API. An example of application is the [BitcoinWallet](https://github.com/Toporin/BitcoinWallet) java application, that uses SatoChipClient through another Bitcoin library called [BitcoinCore](https://github.com/Toporin/BitcoinCore).  

# Credits

- The CardEdge javacard applet is derived from the [MUSCLE framework](http://pcsclite.alioth.debian.org/musclecard.com/info.html).
- The Bitcoin transaction parser is derived from [Btchip](https://github.com/LedgerHQ/btchipJC).
- The BitcoinWallet application is based on ScripterRon [BitcoinWallet](https://github.com/ScripterRon/BitcoinWallet) client and [BitcoinCore](https://github.com/ScripterRon/BitcoinCore) library.

# License

This application is distributed under the GNU Affero General Public License version 3.

Some parts of the code may be licensed under a different (MIT-like) license. 
[Contact us](mailto:support@satochip.io) if you feel that some license combination is inappropriate.

