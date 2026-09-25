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

There are two ways to generate the CAP file from the sources: the [Gradle](#building-using-gradle) build (recommended, builds both applets of the package and can install them on a card), or the legacy [Ant](#building-using-ant-legacy) build using the [ant-javacard](https://github.com/martinpaljak/ant-javacard) task (builds the `CardEdge` applet only).

## Building using Ant (legacy)

* Clone Satochip applet repository:
```
git clone https://github.com/Toporin/SatochipApplet.git
```

* Download Ant-Javacard [latest release](https://github.com/martinpaljak/ant-javacard) in the `lib` folder:
```
https://github.com/martinpaljak/ant-javacard/releases/latest/download/ant-javacard.jar
```

* Install [Apache Ant](https://ant.apache.org/srcdownload.cgi):
```
sudo apt install ant
```

* Use/install [recommended](https://github.com/martinpaljak/ant-javacard/wiki/JavaCard-SDK-and-JDK-version-compatibility) java JDK 8 or 11
```
sudo update-alternatives --config java
```

* Download javacard SDK into satochip project in `sdks` folder:
```
git submodule add https://github.com/martinpaljak/oracle_javacard_sdks sdks
```

* run ant:
```ant```

The .cap file should build in the SatochipApplet folder.

## Building using Gradle

The Gradle build is the recommended one: it builds **both** applets contained in the package
(`CardEdge` and `NDEFApplet`) and can also install them on a card without GlobalPlatformPro.
The Ant build above is kept as the legacy path and only builds `CardEdge`.

### Requirements

* **OpenJDK 11**, with `JAVA_HOME` pointing at it. The build uses Gradle 4.10 with
  `sourceCompatibility 1.6`, which requires a JDK no newer than 11. JDK 8 is *not* enough either,
  because some build dependencies are compiled for Java 11.
```
sudo apt install openjdk-11-jdk
export JAVA_HOME=/usr/lib/jvm/java-11-openjdk-amd64
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

This repository has no test suite of its own: the applet is tested from the client side, over the APDU interface, by the [pysatochip](https://github.com/Toporin/pysatochip) library. It provides both offline tests, which check the client and pin a BIP340/BIP341 reference implementation to the official Bitcoin test vectors, and hardware tests, which run the applet's BIP32 derivation, message signing, taproot/schnorr and MuSig2 commands against a card and compare the results to those vectors.

See the [Running the Tests](https://github.com/Toporin/pysatochip#running-the-tests) section of the pysatochip README for the test list and how to run them. Note that the hardware tests are destructive: only run them against a development card.

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

