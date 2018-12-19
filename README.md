# SatoChipApplet
Open source javacard applet implementing a Bitcoin hardware wallet with full BIP32 support

# Demonstration 

[![demonstrationon youtube](http://img.youtube.com/vi/ADWikh8Fxdk/0.jpg)](http://www.youtube.com/watch?v=ADWikh8Fxdk)

# Introduction

SatoChip stands for Secure Anonymous Trustless and Open Chip. It is a javacard applet that can be used as a secure hardware wallet running for example on a [Yubikey Neo](https://store.yubico.com/store/catalog/product_info.php?ref=368&products_id=72&affiliate_banner_id=1). The SatoChip has full BIP32 supports but due to technical limitations on current javacards, *hardened keys* (i.e. child keys using indices 2^31 through 2^32-1) are derived much faster than normal keys.

Using SatoChip, an initial BIP32 seed is imported in the javacard and private keys are derived as requested by an external application. *Private keys are never exported outside of the secure chip*. Private key derivation is actually rather slow due to the fact that BIP32 derivation requires HMAC-SHA512, which is not natively available on current javacards. Hence the applet uses a [software implementation]. To improve performances, the result of key derivation is cached in secure memory for future requests so that derivation is only computed once.

The SatoChip also supports the import of regular (non-BIP32 keys) such as vanity keys. Here again, private keys cannot be exported outside of the secure chip. Up to 16 regular keys can be imported on the chip. In any case, the private keys can be used to sign transactions and Bitcoin messages, if sufficient credentials are provided.

Access to private keys (creation, derivation and signature) is enforced through the use of PIN code. This access control is based on the [MUSCLE framework](http://pcsclite.alioth.debian.org/musclecard.com/index.html) on which the applet is built. As part of this framework, it is also possible to securely store and retrieve data objects in secure memory, or use the chip to perform encryption and decryption, although some functionalities have been disabled.

Please note that this implementation is currently under development: *Use it at your own risk!*. I cannot be held responsible for any loss incurred by the use of this application. 

Advantages:
- Code is free and open source (no NDA required!)
- Code easy to read and maintain (java card is a subset of java)
- Multiple form factor could be supported in addition to Yubikey (e.g sim cards)
- Plug and play
- Smartcards have a long experience in dealing with security and physical security in particular
- Can be easily used or extended for other crypto-currencies
- A test package is run during build to ensure that critical functionalities are implemented correctly

Also, if used with a Yubikey:
- Yubikey has minimal size and is practically indestructible
- The Yubico company is not going anywhere anytime soon! 
- Many promising functionalities: NFC, Yubikey OTP, U2F, ...
- Possibility to use the HMAC-SHA1 challenge-response of the Yubikey as second factor for additional security against malwares

Disadvantages:
- This is still experimental code, use with caution!
- Key derivation is a bit slow(derive a new hardened key takes about 10 seconds)
- Building the applet is a bit tricky
- The software implementation of HMAC-SHA512 could have an potential impact on the physical security against side-channel attacks (for attackers with physical access to the chip).

# Supported hardware

To support Bitcoin signatures, the javacard must support ALG_ECDSA_SHA_256, which in practice requires a javacard compliant with the JavaCard 3.0.1 specification. Note that this is a necessary but not sufficient condition since javacards typically implements only a subset of the specification.
A detailed list of javacard and their supported features is available [here](http://www.fi.muni.cz/~xsvenda/jcsupport.html).

An interesting guide to consult before shopping can be found [here](https://github.com/martinpaljak/GlobalPlatformPro/tree/master/docs/JavaCardBuyersGuide)

## tested and working

### Yubikey Neo
**Important remark:** the Yubikeys currently sold by Yubico are configured for production only and it is not possible to load the applet on these dongles (see [this link](https://www.yubico.com/2014/07/yubikey-neo-updates/) for more details). Only the development Yubikeys (with serial number below 3,000,000) are suitable for our use! 

### NXP JCOP J2D081
Available for purchase [here](http://www.javacardsdk.com/Index.aspx?p0=AAT1P0000012&p1=1&p2=1&p3=1&p4=0&p5=1) (minimum quantity order: 5 pieces)

### Swissbit PS-100u VE card Secure micro SD memory card
More info [here](http://www.swissbit.com/index.php?option=com_content&view=article&id=293&Itemid=601)
(Note however that Swissbit does not sell its product directly to end users but only to business partners)

## Not tested but should work

### J3D081 JCOP v2.4.2 R2
Available [here](http://www.motechno.com/javacard3.0.html)


# Build

You can build the javacard CAP files or use the last [version built](https://github.com/Toporin/SatoChipApplet/blob/master/src/org/satochip/applet/javacard/applet.cap).

To generate the CAP file from the sources, you can use Eclipse with the JCDE plugin and the Java Card Development Kit:

- Download the [Java Card Development Kit 2.2.2](http://www.oracle.com/technetwork/java/javasebusiness/downloads/java-archive-downloads-javame-419430.html#java_card_kit-2.2.2-oth-JPR) 
- Download Eclipse from https://eclipse.org/downloads/
- Download the JCDE plugin from http://eclipse-jcde.sourceforge.net/

A short introduction to the use of the JCDE plugin for javacard development is provided [here](http://eclipse-jcde.sourceforge.net/user-guide.htm)
Here is an [alternative description](https://github.com/Yubico/ykneo-openpgp/blob/master/doc/Building.txt) from Yubico. 

In principle, you could also use Netbeans and the more appropriate JCDK 3.0.3 to build the CAP file. However, I had a hard time setting this up and use it with the Yubikey, so I ended up using Eclipse with some workaround instead. 

# Install

Once you have a CAP file, you have to download it on the chip card. You can use GPJ to do this:

- Download GPJ from http://sourceforge.net/projects/gpj/
- (Put the CAP file in the same folder as the GPJ jar file for convenience)
- To list the applets loaded on a smartcard: `java -jar gpj.jar -list`
- To load the SatoChip applet: `java -jar gpj.jar -load applet.cap -install`
- To delete the SatoChip applet (AID 0x53:0x61:0x74:0x6f:0x43:0x68:0x69:0x70): `java -jar gpj.jar -deletedeps -delete 5361746f43686970`

Here is a [link](http://forum.yubico.com/viewtopic.php?ref=368&f=26&t=1159) describing the procedure specifically for the Yubikey Neo (using GPshell instead of GPJ).

# Use

To use the applet, you have to connect your client application to the smartcard and send command APDU. These commands will be processed by the smartcard who will then send a response APDU. [SatoChipClient](https://github.com/Toporin/SatoChipClient) is a small java library that allows to easily interface the SatoChip applet to your application through a simple set of API.
An example of application is the [BitcoinWallet](https://github.com/Toporin/BitcoinWallet) java application, that uses SatoChipClient through another Bitcoin library called [BitcoinCore](https://github.com/Toporin/BitcoinCore).  

# Credits

- The CardEdge javacard applet is based on the [MUSCLE framework](http://pcsclite.alioth.debian.org/musclecard.com/info.html).
- The [HMAC-SHA512](http://www.fi.muni.cz/~xsvenda/jcalgs.html#sha2) implementation is from [Petr Svenda](http://www.fi.muni.cz/~xsvenda/).
- The Bitcoin transaction parser is derived from [Btchip](https://github.com/LedgerHQ/btchipJC).
- The BitcoinWallet application is based on ScripterRon [BitcoinWallet](https://github.com/ScripterRon/BitcoinWallet) client and [BitcoinCore](https://github.com/ScripterRon/BitcoinCore) library.

# License

This application is distributed under the GNU Affero General Public License version 3.

Some parts of the code may be licensed under a different (MIT-like) license. [Contact me](mailto:satochip.wallet@gmail.com) if you feel that some license combination is inappropriate.

