# Satochip Applet

---
## Demonstration 

🎥 [Satochip - How to setup your hardware wallet with Sparrow Wallet](https://youtu.be/Y-bmiHC5PRk?feature=shared)

[![How to setup your hardware wallet with Sparrow Wallet](https://i.ytimg.com/an_webp/Y-bmiHC5PRk/mqdefault_6s.webp?du=3000&sqp=CPSkkr0G&rs=AOn4CLCStGYlrAP3cGdRun7rkdTga8GVPA)](https://youtu.be/Y-bmiHC5PRk?feature=shared)

---
## Introduction

Satochip stands for **S**ecure **A**nonymous **T**rustless and **O**pen **Chip**. 
It is a javacard applet that can be used as a secure hardware wallet running on multiple form-factor.
The Satochip applet has full BIP32/BIP39 supports.

Using Satochip, an initial BIP32 seed is imported in the javacard and private keys are derived as requested by an external application. *Private keys are never exported outside of the secure chip*. To improve performances, the result of key derivation is cached in secure memory for future requests so that a specific derivation path is only computed once.

The Satochip also supports the import of regular (non-BIP32 keys) such as vanity keys. Here again, private keys cannot be exported outside of the secure chip. Up to 16 regular keys can be imported on the chip. In any case, the private keys can be used to sign transactions and Bitcoin messages, if sufficient credentials are provided.

Access to private keys (creation, derivation and signature) is enforced through the use of PIN code (from 4 to 16 chars).

### Advantages:
- Code is free and open source (no NDA required);
- Code is easy to read and maintain (javacard is a subset of java);
- Multiple form factor could be supported (e.g smartcard, sim card, ring, tag...);
- Plug and play;
- Smartcards have a long experience in dealing with security and physical security in particular;
- Can be easily used or extended for other crypto-currencies;
- A test package is run during build to ensure that critical functionalities are implemented correctly.

Also:
- Smartcard has minimal size and is weatherproof;
- Many interesting functionalities: NFC, PGP, U2F, ...;
- Possibility to use the HMAC-SHA1 challenge-response as second factor for additional security against malwares.

### Disadvantages:
- Building the applet might be a bit tricky;
- The software implementation of HMAC-SHA512 could have an potential impact on the physical security against side-channel attacks (for attackers with physical access to the chip).

---
## Supported hardware

To support Bitcoin signatures, the javacard must support ALG_ECDSA_SHA_256, which in practice requires a javacard compliant with the JavaCard 3.0.1 specification. 
Note that this is a necessary but not sufficient condition since javacards typically implements only a subset of the specification.
A detailed list of javacard and their supported features is available [here](http://www.fi.muni.cz/~xsvenda/jcsupport.html).

An interesting guide to consult before shopping can be found [here](https://github.com/martinpaljak/GlobalPlatformPro/tree/master/docs/JavaCardBuyersGuide).

### Tested and working

Navigating the javacard ecosystem can be tricky, as there are many different configuration options even within the same chipset. Here is a non-exhaustive list of tested smartcards and devices.

#### Yubikey Neo
**Important remark:** the Yubikeys currently sold by Yubico are configured for production only and it is not possible to load the applet on these dongles (see [this link](https://www.yubico.com/2014/07/yubikey-neo-updates/) for more details). 
Only the development Yubikeys (with serial number below 3,000,000) are suitable for our use! 

#### NXP JCOP4 P71 SECID based javacard 
- J3R110
- J3R180
- J3R200 -> Recommended card, buy yours at [the official Satochip website](https://satochip.io/product/card-for-diy-project/)
  - Also exist in SIM form factor, available [here](https://satochip.io/product/blank-sim-javacard-for-diy-project/). 

#### NXP JCOP3 P60 SECID based javacard
- J3H145

---
## Buidl

You can build the javacard CAP files or use the lastest [built version available](https://github.com/Toporin/SatochipApplet/releases).
To generate the CAP file from the sources, you can use the [ant-javacard](https://github.com/martinpaljak/ant-javacard) Ant task. _(See the instruction on the ant-javacard github repository)._

### Building on Ubuntu

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

### Load the applet into card

Once you have a CAP file, you have to upload it on your smartcard. 
You can use [GlobalPlatformPro](https://github.com/martinpaljak/GlobalPlatformPro) to do this:

- Download the latest release from https://github.com/martinpaljak/GlobalPlatformPro/releases
- (Put the CAP file in the same folder as the GPJ jar file for convenience)
- To list the applets loaded on a smartcard: `gp.exe -l`
- To load the SatoChip applet: `gp.exe -install .\SatoChip-0.12-05.cap`
- To delete the SatoChip applet: `gp.exe -uninstall .\SatoChip-0.12-05.cap`
- You can also use the gp.jar library: `java -jar gp.jar -install .\SatoChip-0.12-05.cap`

A more detailed tutorial is available on the GlobalPlatformPro [repository](https://github.com/martinpaljak/GlobalPlatformPro).

A specific tutorial for the Satochip applet is available on the [Satochip Academy](https://satochip.io/build-your-own-satochip-hardware-wallet/).

---
## Usage

To use the applet, you have to connect your client application to the smartcard and send command APDU. These commands will be processed by the smartcard who will then send a response APDU. 

### Supported software clients

- Bitcoin (BTC):
  - [Sparrow Wallet](https://sparrowwallet.com/download/). _(Satochip is natively supported since v.1.8.0)_
  - [Electrum-Satochip](https://github.com/Toporin/electrum-satochip/releases) is a version of [Electrum](https://github.com/spesmilo/electrum) that was slightly modified to integrate the Satochip hardware wallet.

- Litecoin (LTC): 
  - [Litecoin Electrum-Satochip](https://github.com/Toporin/electrum-satochip/releases) is a version of [Electrum for Litecoin](https://github.com/pooler/electrum-ltc/) that was slightly modified to integrate the Satochip hardware wallet.

- Bitcoin Cash (BCH):
  -[Electron-Cash](https://electroncash.org/). _(Satochip is natively supported since v.4.0.11)_

- eCash (XEC): 
  - [Electrum ABC](https://www.bitcoinabc.org/electrum). _(Satochip is natively supported since v.4.0.11)_

- Ethereum (ETH), Polygon (POL), Binance Smart Chain (BSC), Tezos (XTZ) and many other EVM-compatible blockchains:
  - [Uniblow](https://uniblow.org/get). _(Satochip is natively supported since v.2.6.0)_

- The [Wallet Connect protocol](https://satochip.io/wallet-connect/) is also supported through [Uniblow](https://uniblow.org/get)
  - See [this step-by-step tutorial to use your Satochip hardware wallet](https://satochip.io/satochip-rabby-wallet/) with [Rabby](https://rabby.io/) - through the Wallet Connect protocol

---
## Credits

- The CardEdge javacard applet is derived from the [MUSCLE framework](http://pcsclite.alioth.debian.org/musclecard.com/info.html).
- The Bitcoin transaction parser is derived from [Btchip](https://github.com/LedgerHQ/btchipJC).
- The BitcoinWallet application is based on ScripterRon [BitcoinWallet](https://github.com/ScripterRon/BitcoinWallet) client and [BitcoinCore](https://github.com/ScripterRon/BitcoinCore) library.

---
## License

This application is distributed under the GNU Affero General Public License version 3.

Some parts of the code may be licensed under a different (MIT-like) license. 
[Contact us](mailto:support@satochip.io) if you feel that some license combination is inappropriate.

