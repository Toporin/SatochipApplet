/*
 * SatoChip Bitcoin Hardware Wallet based on javacard
 * (c) 2015-2019 by Toporin - 16DMCk4WUaHofchAhpMaQS4UPm4urcy2dN
 * Sources available on https://github.com/Toporin					 
 * Changes include: -Bip32 support
 * 					-simple Bitcoin transaction signatures 
 * 					-Bitcoin message signatures
 * 					
 *  
 * Based on the M.US.C.L.E framework:
 * see http://pcsclite.alioth.debian.org/musclecard.com/musclecard/
 * see https://github.com/martinpaljak/MuscleApplet/blob/d005f36209bdd7020bac0d783b228243126fd2f8/src/com/musclecard/CardEdge/CardEdge.java
 * 
 *  MUSCLE SmartCard Development
 *      Authors: Tommaso Cucinotta <cucinotta@sssup.it>
 *	         	 David Corcoran    <corcoran@linuxnet.com>
 *	    Description:      CardEdge implementation with JavaCard
 *      Protocol Authors: Tommaso Cucinotta <cucinotta@sssup.it>
 *		                  David Corcoran <corcoran@linuxnet.com>
 *      
 * BEGIN LICENSE BLOCK
 * Copyright (C) 1999-2002 David Corcoran <corcoran@linuxnet.com>
 * Copyright (C) 2015-2019 Toporin 
 * All rights reserved.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 * END LICENSE_BLOCK  
 */

package org.satochip.applet;

import javacard.framework.APDU;
//import javacard.framework.CardRuntimeException;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN;
import javacard.framework.SystemException;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
//import javacard.security.HMACKey;
import javacard.security.Key;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;
import javacard.security.Signature;
import javacard.security.MessageDigest;
import javacard.security.RandomData;
import javacardx.apdu.ExtendedLength; //debugXL //TODO: remove
import javacardx.crypto.Cipher;

/**
 * Implements MUSCLE's Card Edge Specification.
 */
public class CardEdge extends javacard.framework.Applet implements ExtendedLength { 

	/* constants declaration */
	
	/** 
	 * VERSION HISTORY
	 * PROTOCOL VERSION: changes that impact compatibility with the client side
	 * APPLET VERSION:   changes with no impact on compatibility of the client
	 */
	// 0.1-0.1: initial version
	// 0.2-0.1: support for hmac-sha1 authorisation + improved sha256 + bip32 full support  
	// 0.3-0.1: change parseTransaction response for coherence: add separate short flags for second factor authentication  
	// 0.3-0.2: fast Sha512 computation  
    // 0.4-0.1: getBIP32ExtendedKey also returns chaincode
	// 0.5-0.1: Support for Segwit transaction
	// 0.5-0.2: bip32 cached memory optimisation: fixed array instead of list 
	// 0.6-0.1: bip32 optimisation: speed up computation during derivation of non-hardened child 
	// 0.6-0.2: get_status returns number of pin/puk tries remaining
    // 0.6-0.3: Patch in function SignTransaction(): add optional 2FA flag in data
    // 0.7-0.1: add CryptTransaction2FA() to encrypt/decrypt tx messages sent to 2FA device for privacy
	// 0.7-0.2: 2FA patch to mitigate replay attack when importing a new seed
	// 0.8-0.1: add APDU to reset the seed, with 2FA support. 2FA can be disabled, only when seed is reset.
	private final static byte PROTOCOL_MAJOR_VERSION = (byte) 0; 
	private final static byte PROTOCOL_MINOR_VERSION = (byte) 8;
	private final static byte APPLET_MAJOR_VERSION = (byte) 0;
	private final static byte APPLET_MINOR_VERSION = (byte) 1;
	
	// Maximum number of keys handled by the Cardlet
	private final static byte MAX_NUM_KEYS = (byte) 16;
	// Maximum number of PIN codes
	private final static byte MAX_NUM_PINS = (byte) 8; // TODO: set to 2?

	// Maximum size for the extended APDU buffer 
	private final static short EXT_APDU_BUFFER_SIZE = (short) 268;
	private final static short TMP_BUFFER_SIZE = (short) 256;

	// Minimum PIN size
	private final static byte PIN_MIN_SIZE = (byte) 4;
	// Maximum PIN size
	private final static byte PIN_MAX_SIZE = (byte) 16;// TODO: increase size?
	// PIN[0] initial value...
	private final static byte[] PIN_INIT_VALUE={(byte)'M',(byte)'u',(byte)'s',(byte)'c',(byte)'l',(byte)'e',(byte)'0',(byte)'0'};

	// code of CLA byte in the command APDU header
	private final static byte CardEdge_CLA = (byte) 0xB0;

	/****************************************
	 * Instruction codes *
	 ****************************************/

	// Applet initialization
	private final static byte INS_SETUP = (byte) 0x2A;

	// Keys' use and management
	private final static byte INS_IMPORT_KEY = (byte) 0x32;
	//private final static byte INS_EXPORT_KEY = (byte) 0x34;
	private final static byte INS_GET_PUBLIC_FROM_PRIVATE= (byte)0x35;
	
	// External authentication
	private final static byte INS_CREATE_PIN = (byte) 0x40; //TODO: remove?
	private final static byte INS_VERIFY_PIN = (byte) 0x42;
	private final static byte INS_CHANGE_PIN = (byte) 0x44;
	private final static byte INS_UNBLOCK_PIN = (byte) 0x46;
	private final static byte INS_LOGOUT_ALL = (byte) 0x60;
	
	// Status information
	private final static byte INS_LIST_PINS = (byte) 0x48;
	private final static byte INS_GET_STATUS = (byte) 0x3C;
	
	// HD wallet
	private final static byte INS_BIP32_IMPORT_SEED= (byte) 0x6C;
	private final static byte INS_BIP32_RESET_SEED= (byte) 0x77;
	private final static byte INS_BIP32_GET_AUTHENTIKEY= (byte) 0x73;
	private final static byte INS_BIP32_SET_AUTHENTIKEY_PUBKEY= (byte)0x75;
	private final static byte INS_BIP32_GET_EXTENDED_KEY= (byte) 0x6D;
	private final static byte INS_BIP32_SET_EXTENDED_PUBKEY= (byte) 0x74;
	private final static byte INS_SIGN_MESSAGE= (byte) 0x6E;
	private final static byte INS_SIGN_SHORT_MESSAGE= (byte) 0x72;
	private final static byte INS_SIGN_TRANSACTION= (byte) 0x6F;
	private final static byte INS_PARSE_TRANSACTION = (byte) 0x71;
    private final static byte INS_CRYPT_TRANSACTION_2FA = (byte) 0x76;
    private final static byte INS_GET_COUNTER_2FA = (byte) 0x78;
    private final static byte INS_SET_2FA_KEY = (byte) 0x79;    
    
	// debug
	private final static byte INS_TEST_SHA1 = (byte) 0x80;
	private final static byte INS_COMPUTE_SHA512 = (byte) 0x6A;
	private final static byte INS_COMPUTE_HMAC= (byte) 0x6B;
	private final static byte INS_BIP32_SET_EXTENDED_KEY= (byte) 0x70;
	

	/** There have been memory problems on the card */
	private final static short SW_NO_MEMORY_LEFT = Bip32ObjectManager.SW_NO_MEMORY_LEFT;
	/** Entered PIN is not correct */
	private final static short SW_AUTH_FAILED = (short) 0x9C02;
	/** Required operation is not allowed in actual circumstances */
	private final static short SW_OPERATION_NOT_ALLOWED = (short) 0x9C03;
	/** Required setup is not not done */
	private final static short SW_SETUP_NOT_DONE = (short) 0x9C04;
	/** Required setup is already done */
	private final static short SW_SETUP_ALREADY_DONE = (short) 0x9C07;
	/** Required feature is not (yet) supported */
	private final static short SW_UNSUPPORTED_FEATURE = (short) 0x9C05;
	/** Required operation was not authorized because of a lack of privileges */
	private final static short SW_UNAUTHORIZED = (short) 0x9C06;
	/** Algorithm specified is not correct */
	private final static short SW_INCORRECT_ALG = (short) 0x9C09;
	/** Required object is missing */
	private final static short SW_OBJECT_NOT_FOUND= (short) 0x9C07;

	/** Incorrect P1 parameter */
	private final static short SW_INCORRECT_P1 = (short) 0x9C10;
	/** Incorrect P2 parameter */
	private final static short SW_INCORRECT_P2 = (short) 0x9C11;
	/** Invalid input parameter to command */
	private final static short SW_INVALID_PARAMETER = (short) 0x9C0F;

	/** Verify operation detected an invalid signature */
	private final static short SW_SIGNATURE_INVALID = (short) 0x9C0B;
	/** Operation has been blocked for security reason */
	private final static short SW_IDENTITY_BLOCKED = (short) 0x9C0C;
	/** For debugging purposes */
	private final static short SW_INTERNAL_ERROR = (short) 0x9CFF;
	/** Very low probability error */
	private final static short SW_BIP32_DERIVATION_ERROR = (short) 0x9C0E;
	/** Incorrect initialization of method */
	private final static short SW_INCORRECT_INITIALIZATION = (short) 0x9C13;
	/** Bip32 seed is not initialized*/
	private final static short SW_BIP32_UNINITIALIZED_SEED = (short) 0x9C14;
	/** Bip32 seed is already initialized (must be reset before change)*/
	private final static short SW_BIP32_INITIALIZED_SEED = (short) 0x9C17;
	/** Bip32 authentikey pubkey is not initialized*/
	private final static short SW_BIP32_UNINITIALIZED_AUTHENTIKEY_PUBKEY= (short) 0x9C16;
	/** Incorrect transaction hash */
	private final static short SW_INCORRECT_TXHASH = (short) 0x9C15;
	
	/** 2FA already initialized*/
	private final static short SW_2FA_INITIALIZED_KEY = (short) 0x9C18;
	/** 2FA uninitialized*/
	private final static short SW_2FA_UNINITIALIZED_KEY = (short) 0x9C19;
	
	/** For debugging purposes 2 */
	private final static short SW_DEBUG_FLAG = (short) 0x9FFF;
	
	// KeyBlob Encoding in Key Blobs
	private final static byte BLOB_ENC_PLAIN = (byte) 0x00;

	// Cipher Operations admitted in ComputeCrypt()
	private final static byte OP_INIT = (byte) 0x01;
	private final static byte OP_PROCESS = (byte) 0x02;
	private final static byte OP_FINALIZE = (byte) 0x03;

	// JC API 2.2.2 does not define these constants:
	private final static byte ALG_ECDSA_SHA_256= (byte) 33;
	private final static byte ALG_EC_SVDP_DH_PLAIN= (byte) 3; //https://javacard.kenai.com/javadocs/connected/javacard/security/KeyAgreement.html#ALG_EC_SVDP_DH_PLAIN
	private final static short LENGTH_EC_FP_256= (short) 256;
		
	/****************************************
	 * Instance variables declaration *
	 ****************************************/
	
	// Key objects (allocated on demand)
	private Key[] eckeys;
	private ECPrivateKey tmpkey;
	boolean eckeys_used=false;
	
	// PIN and PUK objects, allocated on demand
	private OwnerPIN[] pins, ublk_pins;

	// Buffer for storing extended APDUs
	private byte[] recvBuffer;
	private byte[] tmpBuffer;

	/*
	 * Logged identities: this is used for faster access control, so we don't
	 * have to ping each PIN object
	 */
	private short logged_ids;

	/* For the setup function - should only be called once */
	private boolean setupDone = false;
	
	// shared cryptographic objects
	private RandomData randomData;
	private KeyAgreement keyAgreement;
	private Signature sigECDSA;
	private Cipher aes128;
    
	/*********************************************
	 *  BIP32 Hierarchical Deterministic Wallet  *
	 *********************************************/
	// Secure Memory & Object Manager with no access from outside (used internally for storing BIP32 objects)
	private Bip32ObjectManager bip32_om;
	
	// seed derivation
	private static final byte[] BITCOIN_SEED = {'B','i','t','c','o','i','n',' ','s','e','e','d'};
	private static final byte[] BITCOIN_SEED2 = {'B','i','t','c','o','i','n',' ','s','e','e','d','2'};
	private static final byte MAX_BIP32_DEPTH = 10; // max depth in extended key from master (m/i is depth 1)
	
	// BIP32_object= [ hash(address) (4b) | extended_key (32b) | chain_code (32b) | compression_byte(1b)]
	// recvBuffer=[ parent_chain_code (32b) | 0x00 | parent_key (32b) | hash(address) (32b) | current_extended_key(32b) | current_chain_code(32b) ]
	// hash(address)= [ index(4b) | unused (28-4b) | ANTICOLLISIONHASH(4b)]
	private static final short BIP32_KEY_SIZE= 32; // size of extended key and chain code is 256 bits
	private static final short BIP32_ANTICOLLISION_LENGTH=4; // max 12 bytes so that index+crc + two hashes fit in 32 bits
	private static final short BIP32_OBJECT_SIZE= (short)(2*BIP32_KEY_SIZE+BIP32_ANTICOLLISION_LENGTH+1);  
	
	// offset in working buffer
	private static final short BIP32_OFFSET_PARENT_CHAINCODE=0;
	private static final short BIP32_OFFSET_PARENT_SEPARATOR=BIP32_KEY_SIZE;
	private static final short BIP32_OFFSET_PARENT_KEY=BIP32_KEY_SIZE+1;
	private static final short BIP32_OFFSET_INDEX= (short)(2*BIP32_KEY_SIZE+1);
	private static final short BIP32_OFFSET_COLLISIONHASH= (short)(BIP32_OFFSET_INDEX+BIP32_KEY_SIZE-BIP32_ANTICOLLISION_LENGTH);
	private static final short BIP32_OFFSET_CHILD_KEY= (short)(BIP32_OFFSET_INDEX+BIP32_KEY_SIZE); 
	private static final short BIP32_OFFSET_CHILD_CHAINCODE= (short)(BIP32_OFFSET_CHILD_KEY+BIP32_KEY_SIZE);
	private static final short BIP32_OFFSET_PUB= (short)(BIP32_OFFSET_CHILD_CHAINCODE+BIP32_KEY_SIZE);
	private static final short BIP32_OFFSET_PUBX= (short)(BIP32_OFFSET_PUB+1);
	private static final short BIP32_OFFSET_PUBY= (short)(BIP32_OFFSET_PUBX+BIP32_KEY_SIZE);
	private static final short BIP32_OFFSET_PATH= (short)(BIP32_OFFSET_PUBY+BIP32_KEY_SIZE);
	private static final short BIP32_OFFSET_END= (short)(BIP32_OFFSET_PATH+4*MAX_BIP32_DEPTH);
	private static final short BIP32_OFFSET_SIG= (short)(ISO7816.OFFSET_CDATA+4*MAX_BIP32_DEPTH);//temporary location 
	
	//   bip32 keys
	private boolean bip32_seeded= false;
	private byte bip32_master_compbyte; // compression byte for master key
	private AESKey bip32_masterkey; 
	private AESKey bip32_masterchaincode; 
	private AESKey bip32_encryptkey; // used to encrypt sensitive data in object
	private ECPrivateKey bip32_extendedkey; // object storing last extended key used
	private ECPrivateKey bip32_authentikey; // key used to authenticate data
	private ECPublicKey bip32_pubkey;
	private byte[] authentikey_pubkey;// store authentikey coordx pubkey TODO: create ECPublicKey instead?
	
	/*********************************************
	 *        Other data instances               *
	 *********************************************/
	
	// Message signing
	private static final byte[] BITCOIN_SIGNED_MESSAGE_HEADER = {0x18,'B','i','t','c','o','i','n',' ','S','i','g','n','e','d',' ','M','e','s','s','a','g','e',':','\n'}; //"Bitcoin Signed Message:\n";
	private MessageDigest sha256;  
	private boolean sign_flag= false;
	
	// transaction signing
	private byte[] transactionData;
	private static final byte OFFSET_TRANSACTION_HASH=0;
	private static final byte OFFSET_TRANSACTION_AMOUNT=OFFSET_TRANSACTION_HASH+32;
	private static final byte OFFSET_TRANSACTION_TOTAL=OFFSET_TRANSACTION_AMOUNT+8;
	private static final byte OFFSET_TRANSACTION_SIZE=OFFSET_TRANSACTION_TOTAL+8;
	
	// tx parsing
	private static final byte PARSE_STD=0x00;
	private static final byte PARSE_SEGWIT=0x01;
	
	//2FA data
	private boolean needs_2FA= false;
	private boolean done_once_2FA= false;
	private byte[] data2FA;
	private static final byte OFFSET_2FA_HMACKEY=0;
	private static final byte OFFSET_2FA_ID=OFFSET_2FA_HMACKEY+20;
	private static final byte OFFSET_2FA_LIMIT=OFFSET_2FA_ID+20;
	private static final byte OFFSET_2FA_COUNTER=OFFSET_2FA_LIMIT+8;
	private static final byte OFFSET_2FA_SIZE=OFFSET_2FA_COUNTER+4;
    private static final short HMAC_CHALRESP_2FA=(short)0x8000;
	
    // 2FA msg encryption
    private static final byte[] CST_2FA = {'i','d','_','2','F','A',     
    									   'k','e','y','_','2','F','A'};
    private Cipher aes128_cbc;
    private AESKey key_2FA;
    
	// additional options
	private short option_flags;
	
	/****************************************
	 * Methods *
	 ****************************************/

	private CardEdge(byte[] bArray, short bOffset, byte bLength) {
		// FIXED: something should be done already here, not only with setup APDU
		
		/* If init pin code does not satisfy policies, internal error */
		if (!CheckPINPolicy(PIN_INIT_VALUE, (short) 0, (byte) PIN_INIT_VALUE.length))
		    ISOException.throwIt(SW_INTERNAL_ERROR);

	    ublk_pins = new OwnerPIN[MAX_NUM_PINS];
		pins = new OwnerPIN[MAX_NUM_PINS];

		// DONE: pass in starting PIN setting with instantiation
		/* Setting initial PIN n.0 value */
		pins[0] = new OwnerPIN((byte) 3, (byte) PIN_INIT_VALUE.length);
		pins[0].update(PIN_INIT_VALUE, (short) 0, (byte) PIN_INIT_VALUE.length);
		
		// debug
		register();
	} // end of constructor

	public static void install(byte[] bArray, short bOffset, byte bLength) {
		CardEdge wal = new CardEdge(bArray, bOffset, bLength);
	}

	public boolean select() {
		/*
		 * Application has been selected: Do session cleanup operation
		 */
		LogOutAll();
		return true;
	}

	public void deselect() {
		LogOutAll();
	}

	public void process(APDU apdu) {
		// APDU object carries a byte array (buffer) to
		// transfer incoming and outgoing APDU header
		// and data bytes between card and CAD

		// At this point, only the first header bytes
		// [CLA, INS, P1, P2, P3] are available in
		// the APDU buffer.
		// The interface javacard.framework.ISO7816
		// declares constants to denote the offset of
		// these bytes in the APDU buffer

		if (selectingApplet())
			ISOException.throwIt(ISO7816.SW_NO_ERROR);

		byte[] buffer = apdu.getBuffer();
		// check SELECT APDU command
		if ((buffer[ISO7816.OFFSET_CLA] == 0) && (buffer[ISO7816.OFFSET_INS] == (byte) 0xA4))
			return;
		// verify the rest of commands have the
		// correct CLA byte, which specifies the
		// command structure
		if (buffer[ISO7816.OFFSET_CLA] != CardEdge_CLA)
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);

		byte ins = buffer[ISO7816.OFFSET_INS];
		if (!setupDone && (ins != (byte) INS_SETUP))
			ISOException.throwIt(SW_SETUP_NOT_DONE);
		if (setupDone && (ins == (byte) INS_SETUP))
			ISOException.throwIt(SW_SETUP_ALREADY_DONE);

		switch (ins) {
		case INS_SETUP:
			setup(apdu, buffer);
			break;
		case INS_IMPORT_KEY:
			ImportKey(apdu, buffer);
			break;
		case INS_GET_PUBLIC_FROM_PRIVATE:
			getPublicKeyFromPrivate(apdu, buffer);
			break;
		case INS_VERIFY_PIN:
			VerifyPIN(apdu, buffer);
			break;
		case INS_CREATE_PIN:
			CreatePIN(apdu, buffer);
			break;
		case INS_CHANGE_PIN:
			ChangePIN(apdu, buffer);
			break;
		case INS_UNBLOCK_PIN:
			UnblockPIN(apdu, buffer);
			break;
		case INS_LOGOUT_ALL:
			LogOutAll();
			break;
		case INS_LIST_PINS:
			ListPINs(apdu, buffer);
			break;
		case INS_GET_STATUS:
			GetStatus(apdu, buffer);
			break;
		case INS_BIP32_IMPORT_SEED:
			importBIP32Seed(apdu, buffer);
			break;
		case INS_BIP32_RESET_SEED:
			resetBIP32Seed(apdu, buffer);
			break;
		case INS_GET_COUNTER_2FA:
			getCounter2FA(apdu, buffer);
			break;
		case INS_BIP32_GET_AUTHENTIKEY:
			getBIP32AuthentiKey(apdu, buffer);
			break;
		case INS_BIP32_SET_AUTHENTIKEY_PUBKEY:
			setBIP32AuthentikeyPubkey(apdu, buffer);
			break;
		case INS_BIP32_GET_EXTENDED_KEY:
			getBIP32ExtendedKey(apdu, buffer);
			break;
		case INS_BIP32_SET_EXTENDED_PUBKEY:
			setBIP32ExtendedPubkey(apdu, buffer);
			break;
		case INS_SIGN_MESSAGE:	
			signMessage(apdu, buffer);
			break;
		case INS_SIGN_SHORT_MESSAGE:	
			signShortMessage(apdu, buffer);
			break;
		case INS_SIGN_TRANSACTION:
			SignTransaction(apdu, buffer);
			break;
		case INS_PARSE_TRANSACTION:
			ParseTransaction(apdu, buffer);
			break;
		case INS_SET_2FA_KEY:
			set2FAKey(apdu, buffer);
			break;
        case INS_CRYPT_TRANSACTION_2FA:
            CryptTransaction2FA(apdu, buffer);
            break;
		// only for debugging purpose
		case INS_BIP32_SET_EXTENDED_KEY:	
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED); // only for debug purpose
			//setBIP32ExtendedKey(apdu, buffer);
			break; 
		case INS_COMPUTE_SHA512:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED); // only for debug purpose
			//computeSha512(apdu, buffer);
			break;
		case INS_COMPUTE_HMAC:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED); // only for debug purpose
			//computeHmac(apdu, buffer);
			break;
		case INS_TEST_SHA1:	
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED); // only for debug purpose
			//testSha512(apdu, buffer)
			break; 
		default:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	} // end of process method

	/** 
	 * Setup APDU - initialize the applet and reserve memory
	 * This is done only once during the lifetime of the applet
	 * 
	 * ins: INS_SETUP (0x2A) 
	 * p1: 0x00
	 * p2: 0x00
	 * data: [default_pin_length(1b) | default_pin | 
     *        pin_tries0(1b) | ublk_tries0(1b) | pin0_length(1b) | pin0 | ublk0_length(1b) | ublk0 | 
     *        pin_tries1(1b) | ublk_tries1(1b) | pin1_length(1b) | pin1 | ublk1_length(1b) | ublk1 | 
     *        secmemsize(2b) | RFU(2b) | RFU(3b) |
     *        option_flags(2b) | 
     *        (option): hmacsha1_key(20b) | amount_limit(8b)
     *        ]
	 * where: 
	 * 		default_pin: {0x4D, 0x75, 0x73, 0x63, 0x6C, 0x65, 0x30, 0x30};
	 * 		pin_tries: max number of PIN try allowed before the corresponding PIN is blocked
	 * 		ublk_tries:  max number of UBLK(unblock) try allowed before the PUK is blocked
	 * 		secmemsize: number of bytes reserved for internal memory (storage of Bip32 objects)
	 * 		memsize: number of bytes reserved for memory with external access
	 * 		ACL: creation rights for objects - Key - PIN
	 * 		option_flags: flags to define up to 16 additional options:
	 * 		bit15 set: second factor authentication using hmac-sha1 challenge-response (v0.2-0.1)
	 * 			hmacsha1_key: 20-byte hmac key used for transaction authorization
	 * 			amount_limit: max amount (in satoshis) allowed without confirmation (this includes change value)
	 *  
	 * return: none
	 */
	private void setup(APDU apdu, byte[] buffer) {
		short bytesLeft = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
		if (bytesLeft != apdu.setIncomingAndReceive())
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

		short base = (short) (ISO7816.OFFSET_CDATA);

		byte numBytes = buffer[base++];
		bytesLeft--;

		OwnerPIN pin = pins[0];

		if (!CheckPINPolicy(buffer, base, numBytes))
			ISOException.throwIt(SW_INVALID_PARAMETER);

		if (pin.getTriesRemaining() == (byte) 0x00)
			ISOException.throwIt(SW_IDENTITY_BLOCKED);

		if (!pin.check(buffer, base, numBytes))
			ISOException.throwIt(SW_AUTH_FAILED);
		
		base += numBytes;
		bytesLeft-=numBytes;

		byte pin_tries = buffer[base++];
		byte ublk_tries = buffer[base++];
		numBytes = buffer[base++];
		bytesLeft-=3;

		if (!CheckPINPolicy(buffer, base, numBytes))
			ISOException.throwIt(SW_INVALID_PARAMETER);

		pins[0] = new OwnerPIN(pin_tries, PIN_MAX_SIZE);//TODO: new pin or update pin?
		pins[0].update(buffer, base, numBytes);
		
		base += numBytes;
		bytesLeft-=numBytes;
		numBytes = buffer[base++];
		bytesLeft--;
		
		if (!CheckPINPolicy(buffer, base, numBytes))
			ISOException.throwIt(SW_INVALID_PARAMETER);
		
		ublk_pins[0] = new OwnerPIN(ublk_tries, PIN_MAX_SIZE);
		ublk_pins[0].update(buffer, base, numBytes);
		
		base += numBytes;
		bytesLeft-=numBytes;
		
		pin_tries = buffer[base++];
		ublk_tries = buffer[base++];
		numBytes = buffer[base++];
		bytesLeft-=3;
		
		if (!CheckPINPolicy(buffer, base, numBytes))
			ISOException.throwIt(SW_INVALID_PARAMETER);

		pins[1] = new OwnerPIN(pin_tries, PIN_MAX_SIZE);
		pins[1].update(buffer, base, numBytes);

		base += numBytes;
		bytesLeft-=numBytes;
		numBytes = buffer[base++];
		bytesLeft--;
		
		if (!CheckPINPolicy(buffer, base, numBytes))
			ISOException.throwIt(SW_INVALID_PARAMETER);

		ublk_pins[1] = new OwnerPIN(ublk_tries, PIN_MAX_SIZE);
		ublk_pins[1].update(buffer, base, numBytes);
		base += numBytes;
		bytesLeft-=numBytes;
		
		short secmem_size= Util.getShort(buffer, base);
		base += (short) 2;
		short RFU = Util.getShort(buffer, base); //mem_size deprecated => RFU...
		base += (short) 2;
		bytesLeft-=4;
		
		RFU = buffer[base++]; //create_object_ACL deprecated => RFU
		RFU = buffer[base++]; //create_key_ACL deprecated => RFU
		RFU = buffer[base++]; //create_pin_ACL deprecated => RFU
		bytesLeft-=3;
		
		bip32_om= new Bip32ObjectManager(secmem_size,BIP32_OBJECT_SIZE, BIP32_ANTICOLLISION_LENGTH);
		
		eckeys = new Key[MAX_NUM_KEYS];
		logged_ids = 0x0000; // No identities logged in
		
		// Initialize the extended APDU buffer
		try {
			// Try to allocate the extended APDU buffer on RAM memory
			recvBuffer = JCSystem.makeTransientByteArray((short) EXT_APDU_BUFFER_SIZE, JCSystem.CLEAR_ON_DESELECT);
		} catch (SystemException e) {
			// Allocate the extended APDU buffer on EEPROM memory
			// This is the fallback method, but its usage is really not
			// recommended as after ~ 100000 writes it will kill the EEPROM cells...
			recvBuffer = new byte[EXT_APDU_BUFFER_SIZE];
		}
		// temporary buffer
		try {
			tmpBuffer = JCSystem.makeTransientByteArray((short) TMP_BUFFER_SIZE, JCSystem.CLEAR_ON_DESELECT);
		} catch (SystemException e) {
			tmpBuffer = new byte[TMP_BUFFER_SIZE];
		}

		// shared cryptographic objects
		keyAgreement = KeyAgreement.getInstance(ALG_EC_SVDP_DH_PLAIN, false); 
		sigECDSA= Signature.getInstance(ALG_ECDSA_SHA_256, false); 
		aes128= Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);
		
		// HD wallet
		Sha512.init();
		HmacSha512.init(tmpBuffer);
		//EccComputation.init(tmpBuffer); //debug
		
		// bip32 material
		bip32_seeded= false;
		bip32_master_compbyte=0x04;
		bip32_masterkey= (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_256, false);
		bip32_masterchaincode= (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_256, false);
		bip32_encryptkey= (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
		// object containing the current extended key
		bip32_extendedkey= (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, LENGTH_EC_FP_256, false);
		Secp256k1.setCommonCurveParameters(bip32_extendedkey);
		// key used to authenticate sensitive data from applet
		bip32_authentikey= (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, LENGTH_EC_FP_256, false);
		Secp256k1.setCommonCurveParameters(bip32_authentikey);
		// key used to recover public key from private
		bip32_pubkey= (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, LENGTH_EC_FP_256, false);
		Secp256k1.setCommonCurveParameters(bip32_pubkey);
		authentikey_pubkey= new byte[2*BIP32_KEY_SIZE+1];
		
		// message signing
		sha256= MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
		
		// Transaction signing
		Transaction.init();
		HmacSha160.init(tmpBuffer);
		transactionData= new byte[OFFSET_TRANSACTION_SIZE];
		
		// parse options
		option_flags=0;
		if (bytesLeft>=2){
			option_flags = Util.getShort(buffer, base);
			base+=(short)2;
			bytesLeft-=(short)2;
			// 2FA: transaction confirmation based on hmacsha160
			if ((option_flags & HMAC_CHALRESP_2FA)==HMAC_CHALRESP_2FA){
				data2FA= new byte[OFFSET_2FA_SIZE];
				Util.arrayCopyNonAtomic(buffer, base, data2FA, OFFSET_2FA_HMACKEY, (short)20); 
				base+=(short)20;
				bytesLeft-=(short)20;
				Util.arrayCopyNonAtomic(buffer, base, data2FA, OFFSET_2FA_LIMIT, (short)8); 
				base+=(short)8;
				bytesLeft-=(short)8;
                // set 2FA variables
				randomData = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
                aes128_cbc= Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
                key_2FA= (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
                // hmac derivation for id_2FA & key_2FA
				HmacSha160.computeHmacSha160(data2FA, OFFSET_2FA_HMACKEY, (short)20, CST_2FA, (short)0, (short)6, data2FA, OFFSET_2FA_ID);
                HmacSha160.computeHmacSha160(data2FA, OFFSET_2FA_HMACKEY, (short)20, CST_2FA, (short)6, (short)7, recvBuffer, (short)0);
                key_2FA.setKey(recvBuffer,(short)0); // AES-128: 16-bytes key!!
                // 2FA counter for seed_reset()
                Util.arrayFillNonAtomic(data2FA, OFFSET_2FA_COUNTER, (short)4,(byte)0);
                needs_2FA= true;
                done_once_2FA= true;// some initialization steps should be done only once in the applet lifetime 
			}
		}
		
		setupDone = true;
	}

	/********** UTILITY FUNCTIONS **********/

	/**
	 * Retrieves the Key object to be used w/ the specified key number, key type
	 * (KEY_XX) and size. If exists, check it has the proper key type If not,
	 * creates it.
	 * 
	 * @return Retrieved Key object or throws SW_UNATUTHORIZED,
	 *         SW_OPERATION_NOT_ALLOWED
	 */
	private Key getKey(byte key_nb, byte key_type, short key_size) {
		
		if (eckeys[key_nb] == null) {
			// We have to create the Key
			eckeys[key_nb] = KeyBuilder.buildKey(key_type, key_size, false);
		} else {
			// Key already exists: check size & type
			/*
			 * TODO: As an option, we could just discard and recreate if not of
			 * the correct type, but creates trash objects
			 */
			if ((eckeys[key_nb].getSize() != key_size) || (eckeys[key_nb].getType() != key_type))
				ISOException.throwIt(SW_OPERATION_NOT_ALLOWED);
		}
		return eckeys[key_nb];
	}

	/**
	 * Registers logout of an identity. This must be called anycase when a PIN
	 * verification or external authentication fail
	 */
	private void LogoutIdentity(byte id_nb) {
		logged_ids &= (short) ~(0x0001 << id_nb);
	}

	/** Checks if PIN policies are satisfied for a PIN code */
	private boolean CheckPINPolicy(byte[] pin_buffer, short pin_offset, byte pin_size) {
		if ((pin_size < PIN_MIN_SIZE) || (pin_size > PIN_MAX_SIZE))
			return false;
		return true;
	}

	/****************************************
	 * APDU handlers *
	 ****************************************/	
	
	/** 
	 * This function allows the import of a private ECkey into the card.
	 * The exact key blob contents depend on the key’s algorithm, type and actual
	 * import parameters. The key's number, algorithm type, and parameters are
	 * specified by arguments P1, P2 and DATA.
	 * If 2FA is enabled, a hmac code must be provided.
	 * 
	 * ins: 0x32
	 * p1: private key number (0x00-0x0F)
	 * p2: 0x00
	 * data: [key_encoding(1) | key_type(1) | key_size(2) | RFU(6) | key_blob | (option)HMAC-2FA(20b)] 
	 * return: none
	 */
	private void ImportKey(APDU apdu, byte[] buffer) {
		// check that PIN[0] has been entered previously
		if (!pins[0].isValidated())
			ISOException.throwIt(SW_UNAUTHORIZED);
		
		if (buffer[ISO7816.OFFSET_P2] != (byte) 0x00)
			ISOException.throwIt(SW_INCORRECT_P2);
		byte key_nb = buffer[ISO7816.OFFSET_P1];
		if ((key_nb < 0) || (key_nb >= MAX_NUM_KEYS))
			ISOException.throwIt(SW_INCORRECT_P1);
		
		short bytesLeft = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
		if (bytesLeft != apdu.setIncomingAndReceive())
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		
		/*** Start reading key blob header***/
		// blob header= [ key_encoding(1) | key_type(1) | key_size(2) | RFU(6)]
		// Check entire blob header
		if (bytesLeft < 4)
			ISOException.throwIt(SW_INVALID_PARAMETER);
		// Check Blob Encoding
		short dataOffset = apdu.getOffsetCdata();
		if (buffer[dataOffset] != BLOB_ENC_PLAIN)
			ISOException.throwIt(SW_UNSUPPORTED_FEATURE);
		dataOffset++; // Skip Blob Encoding
		bytesLeft--;
		// we only support elliptic curve private key
        byte key_type = buffer[dataOffset];
		if (key_type!= KeyBuilder.TYPE_EC_FP_PRIVATE)
			ISOException.throwIt(SW_INCORRECT_ALG);
		dataOffset++; // Skip Key Type
		bytesLeft--;
		short key_size = Util.getShort(buffer, dataOffset);
		if (key_size != LENGTH_EC_FP_256)
			ISOException.throwIt(key_size);
		dataOffset += (short) 2; // Skip Key Size
		bytesLeft -= (short) 2;
		dataOffset += (short) 6; // Skip ACL (deprecated)
		bytesLeft -= (short) 6;
		// key_blob=[blob_size(2) | privkey_blob(32)]
		ECPrivateKey ec_prv_key = (ECPrivateKey) getKey(key_nb, key_type, key_size);
        if (bytesLeft < 2)
                ISOException.throwIt(SW_INVALID_PARAMETER);
        short blob_size = Util.getShort(buffer, dataOffset);
        if (blob_size != 32) // only bitcoin
        	ISOException.throwIt(blob_size);
        dataOffset += (short) 2; 
        bytesLeft -= (short) 2;
        if (bytesLeft < (short) (blob_size))
            ISOException.throwIt(SW_INVALID_PARAMETER);
        
        
        // curves parameters are take by default as SECP256k1
        // Satochip default is secp256k1 (over Fp)
        Secp256k1.setCommonCurveParameters(ec_prv_key);
        
        // check 2FA if required
		if(needs_2FA){
			if (bytesLeft<(short)(blob_size+20))
				ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			// we may have to create the tmpkey
			if (tmpkey == null)
				tmpkey = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, LENGTH_EC_FP_256, false);
			// set from secret value
			tmpkey.setS(buffer, dataOffset, blob_size);
			// compute the corresponding partial public key...
			keyAgreement.init(tmpkey);
	        keyAgreement.generateSecret(Secp256k1.SECP256K1, Secp256k1.OFFSET_SECP256K1_G, (short) 65, recvBuffer, (short)0); // compute x coordinate of public key as k*G
	        // hmac of 64-bytes msg: (sha256(btcheader+msg) | 32bytes zero-padding)
			Util.arrayFillNonAtomic(recvBuffer, (short)32, (short)32, (byte)0x00);
			HmacSha160.computeHmacSha160(data2FA, OFFSET_2FA_HMACKEY, (short)20, recvBuffer, (short)0, (short)64, recvBuffer, (short)64);
			if (Util.arrayCompare(buffer, (short)(dataOffset+blob_size), recvBuffer, (short)64, (short)20)!=0)
				ISOException.throwIt(SW_SIGNATURE_INVALID);
		}
        
        // set from secret value
        ec_prv_key.setS(buffer, dataOffset, blob_size);
        eckeys_used= true;
	}
	
	/** 
	 * This function returns the public key associated with a particular private key stored 
	 * in the applet. The exact key blob contents depend on the key’s algorithm and type. 
	 * 
	 * ins: 0x35
	 * p1: private key number (0x00-0x0F)
	 * p2: 0x00
	 * data: none 
	 * return(SECP256K1): [coordx_size(2b) | pubkey_coordx | sig_size(2b) | sig]
	 */
	private void getPublicKeyFromPrivate(APDU apdu, byte[] buffer) {
		// check that PIN[0] has been entered previously
		if (!pins[0].isValidated())
			ISOException.throwIt(SW_UNAUTHORIZED);
		
		if (buffer[ISO7816.OFFSET_P2] != (byte) 0x00)
			ISOException.throwIt(SW_INCORRECT_P2);
		short bytesLeft = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
		if (bytesLeft != apdu.setIncomingAndReceive())
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		byte key_nb = buffer[ISO7816.OFFSET_P1];
		if ((key_nb < 0) || (key_nb >= MAX_NUM_KEYS))
			ISOException.throwIt(SW_INCORRECT_P1);
		
		Key key = eckeys[key_nb];
		// check type and size
		if ((key == null) || !key.isInitialized())
			ISOException.throwIt(SW_INCORRECT_P1);
		if (key.getType() != KeyBuilder.TYPE_EC_FP_PRIVATE)
			ISOException.throwIt(SW_INCORRECT_ALG);		
		if (key.getSize()!= LENGTH_EC_FP_256)
			ISOException.throwIt(SW_INCORRECT_ALG);
		// check the curve param
		if(!Secp256k1.checkCurveParameters((ECPrivateKey)key, recvBuffer, (short)0))
			ISOException.throwIt(SW_INCORRECT_ALG);
				
		// compute the corresponding partial public key...
        keyAgreement.init((ECPrivateKey)key);
        short coordx_size = keyAgreement.generateSecret(Secp256k1.SECP256K1, Secp256k1.OFFSET_SECP256K1_G, (short) 65, buffer, (short)2); // compute x coordinate of public key as k*G
        Util.setShort(buffer, (short)0, coordx_size);
        
        // sign fixed message
        sigECDSA.init(key, Signature.MODE_SIGN);
        short sign_size= sigECDSA.sign(buffer, (short)0, (short)(coordx_size+2), buffer, (short)(coordx_size+4));
        Util.setShort(buffer, (short)(coordx_size+2), sign_size);
        
        // return x-coordinate of public key+signature
        // the client can recover full public-key from the signature or
        // by guessing the compression value () and verifying the signature... 
        apdu.setOutgoingAndSend((short) 0, (short)(2+coordx_size+2+sign_size));
	}		

	/** 
	 * This function creates a PIN with parameters specified by the P1, P2 and DATA
	 * values. P2 specifies the maximum number of consecutive unsuccessful
	 * verifications before the PIN blocks. PIN can be created only if one of the logged identities
	 * allows it. 
	 * 
	 * ins: 0x40
	 * p1: PIN number (0x00-0x07)
	 * p2: max attempt number
	 * data: [PIN_size(1b) | PIN | UBLK_size(1b) | UBLK] 
	 * return: none
	 */
	private void CreatePIN(APDU apdu, byte[] buffer) {
		// check that PIN[0] has been entered previously
		if (!pins[0].isValidated())
			ISOException.throwIt(SW_UNAUTHORIZED);
		
		byte pin_nb = buffer[ISO7816.OFFSET_P1];
		byte num_tries = buffer[ISO7816.OFFSET_P2];
		
		if ((pin_nb < 0) || (pin_nb >= MAX_NUM_PINS) || (pins[pin_nb] != null))
			ISOException.throwIt(SW_INCORRECT_P1);
		/* Allow pin lengths > 127 (useful at all ?) */
		short avail = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
		if (apdu.setIncomingAndReceive() != avail)
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		// At least 1 character for PIN and 1 for unblock code (+ lengths)
		if (avail < 4)
			ISOException.throwIt(SW_INVALID_PARAMETER);
		byte pin_size = buffer[ISO7816.OFFSET_CDATA];
		if (avail < (short) (1 + pin_size + 1))
			ISOException.throwIt(SW_INVALID_PARAMETER);
		if (!CheckPINPolicy(buffer, (short) (ISO7816.OFFSET_CDATA + 1), pin_size))
			ISOException.throwIt(SW_INVALID_PARAMETER);
		byte ucode_size = buffer[(short) (ISO7816.OFFSET_CDATA + 1 + pin_size)];
		if (avail != (short) (1 + pin_size + 1 + ucode_size))
			ISOException.throwIt(SW_INVALID_PARAMETER);
		if (!CheckPINPolicy(buffer, (short) (ISO7816.OFFSET_CDATA + 1 + pin_size + 1), ucode_size))
			ISOException.throwIt(SW_INVALID_PARAMETER);
		pins[pin_nb] = new OwnerPIN(num_tries, PIN_MAX_SIZE);
		pins[pin_nb].update(buffer, (short) (ISO7816.OFFSET_CDATA + 1), pin_size);
		ublk_pins[pin_nb] = new OwnerPIN((byte) 3, PIN_MAX_SIZE);
		// Recycle variable pin_size
		pin_size = (byte) (ISO7816.OFFSET_CDATA + 1 + pin_size + 1);
		ublk_pins[pin_nb].update(buffer, pin_size, ucode_size);
	}

	/** 
	 * This function verifies a PIN number sent by the DATA portion. The length of
	 * this PIN is specified by the value contained in P3.
	 * Multiple consecutive unsuccessful PIN verifications will block the PIN. If a PIN
	 * blocks, then an UnblockPIN command can be issued.
	 * 
	 * ins: 0x42
	 * p1: PIN number (0x00-0x07)
	 * p2: 0x00
	 * data: [PIN] 
	 * return: none (throws an exception in case of wrong PIN)
	 */
	private void VerifyPIN(APDU apdu, byte[] buffer) {
		byte pin_nb = buffer[ISO7816.OFFSET_P1];
		if ((pin_nb < 0) || (pin_nb >= MAX_NUM_PINS))
			ISOException.throwIt(SW_INCORRECT_P1);
		OwnerPIN pin = pins[pin_nb];
		if (pin == null)
			ISOException.throwIt(SW_INCORRECT_P1);
		if (buffer[ISO7816.OFFSET_P2] != 0x00)
			ISOException.throwIt(SW_INCORRECT_P2);
		short numBytes = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
		/*
		 * Here I suppose the PIN code is small enough to enter in the buffer
		 * TODO: Verify the assumption and eventually adjust code to support
		 * reading PIN in multiple read()s
		 */
		if (numBytes != apdu.setIncomingAndReceive())
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		if (!CheckPINPolicy(buffer, ISO7816.OFFSET_CDATA, (byte) numBytes))
			ISOException.throwIt(SW_INVALID_PARAMETER);
		if (pin.getTriesRemaining() == (byte) 0x00)
			ISOException.throwIt(SW_IDENTITY_BLOCKED);
		if (!pin.check(buffer, (short) ISO7816.OFFSET_CDATA, (byte) numBytes)) {
			LogoutIdentity(pin_nb);
			ISOException.throwIt(SW_AUTH_FAILED);
		}
		// Actually register that PIN has been successfully verified.
		logged_ids |= (short) (0x0001 << pin_nb);
	}

	
	/** 
	 * This function changes a PIN code. The DATA portion contains both the old and
	 * the new PIN codes. 
	 * 
	 * ins: 0x44
	 * p1: PIN number (0x00-0x07)
	 * p2: 0x00
	 * data: [PIN_size(1b) | old_PIN | PIN_size(1b) | new_PIN ] 
	 * return: none (throws an exception in case of wrong PIN)
	 */
	private void ChangePIN(APDU apdu, byte[] buffer) {
		/*
		 * Here I suppose the PIN code is small enough that 2 of them enter in
		 * the buffer TODO: Verify the assumption and eventually adjust code to
		 * support reading PINs in multiple read()s
		 */
		byte pin_nb = buffer[ISO7816.OFFSET_P1];
		if ((pin_nb < 0) || (pin_nb >= MAX_NUM_PINS))
			ISOException.throwIt(SW_INCORRECT_P1);
		OwnerPIN pin = pins[pin_nb];
		if (pin == null)
			ISOException.throwIt(SW_INCORRECT_P1);
		if (buffer[ISO7816.OFFSET_P2] != (byte) 0x00)
			ISOException.throwIt(SW_INCORRECT_P2);
		short avail = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
		if (apdu.setIncomingAndReceive() != avail)
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		// At least 1 character for each PIN code
		if (avail < 4)
			ISOException.throwIt(SW_INVALID_PARAMETER);
		byte pin_size = buffer[ISO7816.OFFSET_CDATA];
		if (avail < (short) (1 + pin_size + 1))
			ISOException.throwIt(SW_INVALID_PARAMETER);
		if (!CheckPINPolicy(buffer, (short) (ISO7816.OFFSET_CDATA + 1), pin_size))
			ISOException.throwIt(SW_INVALID_PARAMETER);
		byte new_pin_size = buffer[(short) (ISO7816.OFFSET_CDATA + 1 + pin_size)];
		if (avail < (short) (1 + pin_size + 1 + new_pin_size))
			ISOException.throwIt(SW_INVALID_PARAMETER);
		if (!CheckPINPolicy(buffer, (short) (ISO7816.OFFSET_CDATA + 1 + pin_size + 1), new_pin_size))
			ISOException.throwIt(SW_INVALID_PARAMETER);
		if (pin.getTriesRemaining() == (byte) 0x00)
			ISOException.throwIt(SW_IDENTITY_BLOCKED);
		if (!pin.check(buffer, (short) (ISO7816.OFFSET_CDATA + 1), pin_size)) {
			LogoutIdentity(pin_nb);
			ISOException.throwIt(SW_AUTH_FAILED);
		}
		pin.update(buffer, (short) (ISO7816.OFFSET_CDATA + 1 + pin_size + 1), new_pin_size);
		// JC specifies this resets the validated flag. So we do.
		logged_ids &= (short) ((short) 0xFFFF ^ (0x01 << pin_nb));
	}

	/**
	 * This function unblocks a PIN number using the unblock code specified in the
	 * DATA portion. The P3 byte specifies the unblock code length. 
	 * 
	 * ins: 0x46
	 * p1: PIN number (0x00-0x07)
	 * p2: 0x00
	 * data: [PUK] 
	 * return: none (throws an exception in case of wrong PUK)
	 */
	private void UnblockPIN(APDU apdu, byte[] buffer) {
		byte pin_nb = buffer[ISO7816.OFFSET_P1];
		if ((pin_nb < 0) || (pin_nb >= MAX_NUM_PINS))
			ISOException.throwIt(SW_INCORRECT_P1);
		OwnerPIN pin = pins[pin_nb];
		OwnerPIN ublk_pin = ublk_pins[pin_nb];
		if (pin == null)
			ISOException.throwIt(SW_INCORRECT_P1);
		if (ublk_pin == null)
			ISOException.throwIt(SW_INTERNAL_ERROR);
		// If the PIN is not blocked, the call is inconsistent
		if (pin.getTriesRemaining() != 0)
			ISOException.throwIt(SW_OPERATION_NOT_ALLOWED);
		if (buffer[ISO7816.OFFSET_P2] != 0x00)
			ISOException.throwIt(SW_INCORRECT_P2);
		short numBytes = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
		/*
		 * Here I suppose the PIN code is small enough to fit into the buffer
		 * TODO: Verify the assumption and eventually adjust code to support
		 * reading PIN in multiple read()s
		 */
		if (numBytes != apdu.setIncomingAndReceive())
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		if (!CheckPINPolicy(buffer, ISO7816.OFFSET_CDATA, (byte) numBytes))
			ISOException.throwIt(SW_INVALID_PARAMETER);
		if (!ublk_pin.check(buffer, ISO7816.OFFSET_CDATA, (byte) numBytes))
			ISOException.throwIt(SW_AUTH_FAILED);
		pin.resetAndUnblock();
	}

	private void LogOutAll() {
		logged_ids = (short) 0x0000; // Nobody is logged in
		byte i;
		for (i = (byte) 0; i < MAX_NUM_PINS; i++)
			if (pins[i] != null)
				pins[i].reset();
	}
	
	/**
	 * This function returns a 2 byte bit mask of the available PINs that are currently in
	 * use. Each set bit corresponds to an active PIN.
	 * 
	 *  ins: 0x48
	 *  p1: 0x00
	 *  p2: 0x00
	 *  data: none
	 *  return: [RFU(1b) | PIN_mask(1b)]
	 */
	private void ListPINs(APDU apdu, byte[] buffer) {
		// check that PIN[0] has been entered previously
		if (!pins[0].isValidated())
			ISOException.throwIt(SW_UNAUTHORIZED);
		
		// Checking P1 & P2
		if (buffer[ISO7816.OFFSET_P1] != (byte) 0x00)
			ISOException.throwIt(SW_INCORRECT_P1);
		if (buffer[ISO7816.OFFSET_P2] != (byte) 0x00)
			ISOException.throwIt(SW_INCORRECT_P2);
		byte expectedBytes = (byte) (buffer[ISO7816.OFFSET_LC]);
		if (expectedBytes != (short) 2)
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		// Build the PIN bit mask
		short mask = (short) 0x00;
		short b;
		for (b = (short) 0; b < MAX_NUM_PINS; b++)
			if (pins[b] != null)
				mask |= (short) (((short) 0x01) << b);
		// Fill the buffer
		Util.setShort(buffer, (short) 0, mask);
		// Send response
		apdu.setOutgoingAndSend((short) 0, (short) 2);
	}
	
	/**
	 * This function retrieves general information about the Applet running on the smart
	 * card, and useful information about the status of current session such as:
	 * 		- applet version (4b)
	 *  
	 *  ins: 0x3C
	 *  p1: 0x00 
	 *  p2: 0x00 
	 *  data: none
	 *  return: [versions(4b) | PIN0-PUK0-PIN1-PUK1 tries (4b) | need2FA (1b)]
	 */
	private void GetStatus(APDU apdu, byte[] buffer) {
		// check that PIN[0] has been entered previously
		//if (!pins[0].isValidated())
		//	ISOException.throwIt(SW_UNAUTHORIZED);
		
		if (buffer[ISO7816.OFFSET_P1] != (byte) 0x00)
			ISOException.throwIt(SW_INCORRECT_P1);
		if (buffer[ISO7816.OFFSET_P2] != (byte) 0x00)
			ISOException.throwIt(SW_INCORRECT_P2);
		short pos = (short) 0;
		buffer[pos++] = (byte) PROTOCOL_MAJOR_VERSION; // Major Card Edge Protocol version n.
		buffer[pos++] = (byte) PROTOCOL_MINOR_VERSION; // Minor Card Edge Protocol version n.
		buffer[pos++] = (byte) APPLET_MAJOR_VERSION; // Major Applet version n.
		buffer[pos++] = (byte) APPLET_MINOR_VERSION; // Minor Applet version n.
		// PIN/PUK remaining tries available
		buffer[pos++] = pins[0].getTriesRemaining();
		buffer[pos++] = ublk_pins[0].getTriesRemaining();
		buffer[pos++] = pins[1].getTriesRemaining();
		buffer[pos++] = ublk_pins[1].getTriesRemaining();
		if (needs_2FA)
			buffer[pos++] = (byte)0x01;
		else
			buffer[pos++] = (byte)0x00;
		apdu.setOutgoingAndSend((short) 0, pos);
	}
	
	/**
	 * This function imports a Bip32 seed to the applet and derives the master key and chain code.
	 * It also derives a second ECC that uniquely authenticates the HDwallet: the authentikey.
	 * Lastly, it derives a 32-bit AES key that is used to encrypt/decrypt Bip32 object stored in secure memory 
	 * If the seed already exists, it is reset if the logged identities allow it.
	 * 
	 * The function returns the x-coordinate of the authentikey, self-signed.
	 * The authentikey full public key can be recovered from the signature.
	 *  
	 *  ins: 0x6C
	 *  p1: seed_size(1b) 
	 *  p2: 0x00 
	 *  data: [seed_data (seed_size) | optional-hmac(20b)]
	 *  return: [coordx_size(2b) | coordx | sig_size(2b) | sig]
	 */
	private void importBIP32Seed(APDU apdu, byte[] buffer){
		// check that PIN[0] has been entered previously
		if (!pins[0].isValidated())
			ISOException.throwIt(SW_UNAUTHORIZED);
		if (buffer[ISO7816.OFFSET_P2] != (byte) 0x00)
			ISOException.throwIt(SW_INCORRECT_P2);
		// if already seeded, must call resetBIP32Seed first!
		if (bip32_seeded)
			ISOException.throwIt(SW_BIP32_INITIALIZED_SEED);
		
		short bytesLeft = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
		if (bytesLeft != apdu.setIncomingAndReceive())
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);	
		
		// get seed bytesize (max 64 bytes)
		byte bip32_seedsize = buffer[ISO7816.OFFSET_P1]; 
		if (bip32_seedsize <0 || bip32_seedsize>64)
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		
		short offset= (short)ISO7816.OFFSET_CDATA;
		
		// derive master key!
		HmacSha512.computeHmacSha512(BITCOIN_SEED, (short)0, (short)BITCOIN_SEED.length, buffer, offset, (short)bip32_seedsize, recvBuffer, (short)0);
		bip32_masterkey.setKey(recvBuffer, (short)0); // data must be exactly 32 bytes long
		bip32_masterchaincode.setKey(recvBuffer, (short)32); // data must be exactly 32 bytes long
		
		// derive 2 more keys from seed:
		// - AES encryption key for secure storage of extended keys in object
		// - ECC key for authentication of sensitive data returned by the applet (hash, pubkeys)
		HmacSha512.computeHmacSha512(BITCOIN_SEED2, (short)0, (short)BITCOIN_SEED2.length, buffer, offset, (short)bip32_seedsize, recvBuffer, (short)64);
		bip32_authentikey.setS(recvBuffer, (short)64, BIP32_KEY_SIZE);
		bip32_encryptkey.setKey(recvBuffer, (short)96); // AES-128: 16-bytes key!!
		
		// bip32 is now seeded
		bip32_seeded= true;
		
		// clear recvBuffer
		Util.arrayFillNonAtomic(recvBuffer, (short)0, (short)128, (byte)0);
		
		// compute the partial authentikey public key...
        keyAgreement.init(bip32_authentikey);
        authentikey_pubkey[0]=0x00; // 0x00 means coordy is not set (yet), otherwise 0x04
        short coordx_size = keyAgreement.generateSecret(Secp256k1.SECP256K1, Secp256k1.OFFSET_SECP256K1_G, (short) 65, authentikey_pubkey, (short)1); // compute x coordinate of public key as k*G
        Util.setShort(buffer, (short)0, coordx_size);
        Util.arrayCopyNonAtomic(authentikey_pubkey, (short)1, buffer, (short)2, coordx_size);
        // self signed public key
        sigECDSA.init(bip32_authentikey, Signature.MODE_SIGN);
        short sign_size= sigECDSA.sign(buffer, (short)0, (short)(coordx_size+2), buffer, (short)(coordx_size+4));
        Util.setShort(buffer, (short)(2+coordx_size), sign_size);
        
        // return x-coordinate of public key+signature
        // the client can recover full public-key from the signature or
        // by guessing the compression value () and verifying the signature... 
        // buffer= [coordx_size(2) | coordx | sigsize(2) | sig]
        apdu.setOutgoingAndSend((short) 0, (short)(2+coordx_size+2+sign_size));
	}
	
	/**
	 * This function resets the Bip32 seed and all derived keys: the master key, chain code, authentikey 
	 * and the 32-bit AES key that is used to encrypt/decrypt Bip32 object stored in secure memory.
	 * If 2FA is enabled, then a hmac code must be provided, based on the 4-byte counter-2FA.
	 *  
	 *  ins: 0x77
	 *  p1: PIN_size 
	 *  p2: 0x00 or 0x01 if 2FA should be reset.
	 *  data: [PIN | optional-hmac(20b)]
	 *  return: (none)
	 */
	private void resetBIP32Seed(APDU apdu, byte[] buffer){
		
		short bytesLeft = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
		if (bytesLeft != apdu.setIncomingAndReceive())
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);	
		
		// check provided PIN
		byte pin_size= buffer[ISO7816.OFFSET_P1];
		OwnerPIN pin = pins[(byte)0x00];
		if (bytesLeft < pin_size)
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		if (!CheckPINPolicy(buffer, ISO7816.OFFSET_CDATA, pin_size))
			ISOException.throwIt(SW_INVALID_PARAMETER);
		if (pin.getTriesRemaining() == (byte) 0x00)
			ISOException.throwIt(SW_IDENTITY_BLOCKED);
		if (!pin.check(buffer, (short) ISO7816.OFFSET_CDATA, (byte) pin_size)) {
			LogoutIdentity((byte)0x00);
			ISOException.throwIt(SW_AUTH_FAILED);
		}
		
		// check 2FA if required
		if (needs_2FA){
			short offset= Util.makeShort((byte)0, ISO7816.OFFSET_CDATA);
			offset+=pin_size;
			bytesLeft-= pin_size;
			if (bytesLeft < (short)20)
				ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			
			// compute hmac(counter_2FA) and compare with value provided 
			// hmac of 64-bytes msg: (4bytes counter-2FA | 60bytes zero-padding)
			Util.arrayFillNonAtomic(recvBuffer, (short)0, (short)64, (byte)0x00);
			Util.arrayCopyNonAtomic(data2FA, OFFSET_2FA_COUNTER, recvBuffer, (short)0, (short)4);
			HmacSha160.computeHmacSha160(data2FA, OFFSET_2FA_HMACKEY, (short)20, recvBuffer, (short)0, (short)64, recvBuffer, (short)64);
			if (Util.arrayCompare(buffer, offset, recvBuffer, (short)64, (short)20)!=0)
				ISOException.throwIt(SW_SIGNATURE_INVALID);
			
			//increment counter
			Biginteger.add1_carry(data2FA, OFFSET_2FA_COUNTER, (short)4);
		}		
		// reset memory cache and reset bip32 flag!
		bip32_om.reset();
		bip32_seeded= false;
		
		// disable 2FA if requested
		byte p2= buffer[ISO7816.OFFSET_P2];
		if (p2 == 0x01){
			if (!eckeys_used) // check that no eckey is used
				needs_2FA= false; 
			else
				ISOException.throwIt(SW_OPERATION_NOT_ALLOWED);
		}

		LogOutAll();
		return;
	}
	
	/**
	 * This function returns the authentikey public key (uniquely derived from the Bip32 seed).
	 * The function returns the x-coordinate of the authentikey, self-signed.
	 * The authentikey full public key can be recovered from the signature.
	 * 
	 *  ins: 0x73
	 *  p1: 0x00 
	 *  p2: 0x00 
	 *  data: none
	 *  return: [coordx_size(2b) | coordx | sig_size(2b) | sig]
	 */
	private void getBIP32AuthentiKey(APDU apdu, byte[] buffer){
		// check that PIN[0] has been entered previously
		if (!pins[0].isValidated())
			ISOException.throwIt(SW_UNAUTHORIZED);
		
		// check whether the seed is initialized
		if (!bip32_seeded)
			ISOException.throwIt(SW_BIP32_UNINITIALIZED_SEED);
		
		// compute the partial authentikey public key...
        keyAgreement.init(bip32_authentikey);
        short coordx_size = keyAgreement.generateSecret(Secp256k1.SECP256K1, Secp256k1.OFFSET_SECP256K1_G, (short) 65, buffer, (short)2); // compute x coordinate of public key as k*G
        Util.setShort(buffer, (short)0, coordx_size);
        // self signed public key
        sigECDSA.init(bip32_authentikey, Signature.MODE_SIGN);
        short sign_size= sigECDSA.sign(buffer, (short)0, (short)(coordx_size+2), buffer, (short)(coordx_size+4));
        Util.setShort(buffer, (short)(coordx_size+2), sign_size);
        
        // return x-coordinate of public key+signature
        // the client can recover full public-key from the signature or
        // by guessing the compression value () and verifying the signature... 
        // buffer= [coordx_size(2) | coordx | sigsize(2) | sig]
        apdu.setOutgoingAndSend((short) 0, (short)(coordx_size+sign_size+4));
	}	
	
	/**
	 * This function allows to compute the authentikey pubkey externally and 
	 * store it in the secure memory cache for future use. 
	 * This allows to speed up computation during derivation of non-hardened child.
	 * 
	 * ins: 0x75
	 * p1: 
	 * p2:
	 * data: [coordx_size(2b) | coordx | sig_size(2b) | sig][coordy_size(2b) | coordy]
     *
	 * returns: none
	 */
	private void setBIP32AuthentikeyPubkey(APDU apdu, byte[] buffer){
		// check that PIN[0] has been entered previously
		if (!pins[0].isValidated())
			ISOException.throwIt(SW_UNAUTHORIZED);
		
		// check whether the seed is initialized
		if (!bip32_seeded)
			ISOException.throwIt(SW_BIP32_UNINITIALIZED_SEED);
		
		// input 
		short bytesLeft = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
		if (bytesLeft != apdu.setIncomingAndReceive())
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		
		short offset= (short) ISO7816.OFFSET_CDATA;
		short coordx_size= Util.getShort(buffer, offset);
		offset+=2;
        offset+=coordx_size;
		short sig_size= Util.getShort(buffer, offset);
		offset+=2;
		short offset_sig=offset;
		offset+=sig_size;
		short coordy_size=  Util.getShort(buffer, offset);
		offset+=2;
        // copy pubkey coordy
        Util.arrayCopyNonAtomic(buffer, offset, recvBuffer, (short)(1+coordx_size), coordy_size);
		offset+=coordy_size;
        // copy pubkey coordx from trusted source
		recvBuffer[0]=0x04;
        Util.arrayCopyNonAtomic(authentikey_pubkey, (short)1, recvBuffer, (short)(1), BIP32_KEY_SIZE);
        
        // verify that authentikey signature is valid
        bip32_pubkey.setW(recvBuffer, (short)(0), (short)(1+coordx_size+coordy_size));
		sigECDSA.init(bip32_pubkey, Signature.MODE_VERIFY);
		boolean verify= sigECDSA.verify(buffer, (short)ISO7816.OFFSET_CDATA, (short)(2+coordx_size), buffer, offset_sig, sig_size);
		if (!verify)
			ISOException.throwIt(SW_SIGNATURE_INVALID);
		// copy coordy to secure memory
        authentikey_pubkey[0]=0x04;
        Util.arrayCopyNonAtomic(recvBuffer, (short)(1+BIP32_KEY_SIZE), authentikey_pubkey, (short)(1+BIP32_KEY_SIZE), BIP32_KEY_SIZE);
	
        short pos=0;
		Util.setShort(buffer, pos, bip32_om.nb_elem_free); // number of slot available 
		pos += (short) 2;
		Util.setShort(buffer, pos, bip32_om.nb_elem_used); // number of slot used 
		pos += (short) 2;
		apdu.setOutgoingAndSend((short) 0, pos);
	}// end of setBIP32AuthentikeyPubkey
	
	/**
	 * The function computes the Bip32 extended key derived from the master key and returns the 
	 * x-coordinate of the public key signed by the authentikey.
	 * Extended key is stored in the chip in a temporary EC key, along with corresponding ACL
	 * Extended key and chaincode is also cached as a Bip32 object is secure memory
	 * 
	 * ins: 0x6D
	 * p1: depth of the extended key (master is depth 0, m/i is depht 1). Max depth is 10
	 * p2: 0x00 (default) or 0xFF (erase all Bip32 objects from secure memory)
	 * p2: option flags:
     *		0x80: reset the bip32 cache memory
	 *	 	0x40: optimize non-hardened child derivation
	 *	 	0x20: TODO flag whether to store (save) key as object (currently by default)?
	 * data: index path from master to extended key (m/i/j/k/...). 4 bytes per index
	 * 
	 * returns: [chaincode(32b) | coordx_size(2b) | coordx | sig_size(2b) | sig | sig_size(2b) | sig2]
	 * 
	 * */
	private void getBIP32ExtendedKey(APDU apdu, byte[] buffer){
		// check that PIN[0] has been entered previously
		if (!pins[0].isValidated())
			ISOException.throwIt(SW_UNAUTHORIZED);
		
		// check whether the seed is seed is initialized
		if (!bip32_seeded)
			ISOException.throwIt(SW_BIP32_UNINITIALIZED_SEED);
		
		// input 
		short bytesLeft = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
		if (bytesLeft != apdu.setIncomingAndReceive())
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		
		byte bip32_depth = buffer[ISO7816.OFFSET_P1];
		if ((bip32_depth < 0) || (bip32_depth > MAX_BIP32_DEPTH) )
        	ISOException.throwIt(SW_INCORRECT_P1);
		if (bytesLeft < 4*bip32_depth)
			ISOException.throwIt(SW_INVALID_PARAMETER);
		
		// P2 option flags
		byte opts = buffer[ISO7816.OFFSET_P2]; 
		if ((opts & 0x80)==0x80)
			bip32_om.reset();
		
		// master key data (usefull as parent's data for key derivation)
		// The method uses a temporary buffer recvBuffer to store the parent and extended key object data:
		// recvBuffer=[ parent_chain_code (32b) | 0x00 | parent_key (32b) | hash(address)(32b) | current_extended_key(32b) | current_chain_code(32b) | parent_pubkey(65b) | bip32_path(40b)]
		// hash(address)= [ index(4b) | unused (16b)| crc (4b) | ANTICOLLISIONHASHTMP(4b)| ANTICOLLISIONHASH(4b)]
	    // parent_pubkey(65b)= [compression_byte(1b) | coord_x (32b) | coord_y(32b)]
		bip32_masterchaincode.getKey(recvBuffer, BIP32_OFFSET_PARENT_CHAINCODE);
		bip32_masterkey.getKey(recvBuffer,BIP32_OFFSET_PARENT_KEY); 		
		recvBuffer[BIP32_OFFSET_PARENT_SEPARATOR]=0x00; // separator, also facilitate HMAC derivation
		Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, recvBuffer, BIP32_OFFSET_PATH, (short)(4*bip32_depth));
		short parent_base=Bip32ObjectManager.NULL_OFFSET; 
		
		// iterate on indexes provided 
		short exit_early=0x0000;
		for (byte i=1; i<=bip32_depth; i++){
						
			//compute SHA of the extended key address up to depth i (only the last bytes are actually used)
			sha256.reset(); 
			sha256.doFinal(recvBuffer, BIP32_OFFSET_PATH, (short)(i*4), recvBuffer, BIP32_OFFSET_INDEX);
			short base=bip32_om.getBaseAddress(recvBuffer,BIP32_OFFSET_COLLISIONHASH);
			// retrieve object at this address if it exists
			if (base!=Bip32ObjectManager.NULL_OFFSET){
				bip32_om.getBytes(recvBuffer, BIP32_OFFSET_COLLISIONHASH, base, (short)0, BIP32_OBJECT_SIZE);
			}
			// otherwise, create object if no object was found
			if (base==Bip32ObjectManager.NULL_OFFSET){
				
				// normal or hardened child?
				byte msb= recvBuffer[(short)(BIP32_OFFSET_PATH+4*(i-1))];
				if ((msb & 0x80)!=0x80){ // normal child
					// we must compute parent's compressed pubkey from privkey
					// check if parent's compression byte is available
					byte compbyte=0x04;//default
					if (parent_base==Bip32ObjectManager.NULL_OFFSET)
						compbyte=bip32_master_compbyte;
					else
						compbyte=bip32_om.getByte(parent_base, (short)(BIP32_OBJECT_SIZE-1));
					
					// compute coord x from privkey 
					bip32_extendedkey.setS(recvBuffer, BIP32_OFFSET_PARENT_KEY, BIP32_KEY_SIZE);
					keyAgreement.init(bip32_extendedkey);
					short coordx_size= keyAgreement.generateSecret(Secp256k1.SECP256K1, Secp256k1.OFFSET_SECP256K1_G, (short) 65, recvBuffer, BIP32_OFFSET_PUBX); 
			        
			        // compute compbyte from coord y if necessary (slow!)
			        if (compbyte==0x04 && (opts & 0x40)!=0x40){
				        // coord y= square root of X^3+7 mod p => 2 solutions!
						EccComputation.SqrtRootOpt(recvBuffer, BIP32_OFFSET_PUBX, recvBuffer, BIP32_OFFSET_PUBY);
						recvBuffer[BIP32_OFFSET_PUB]=0x04;
						// sign a dummy message 
						sigECDSA.init(bip32_extendedkey, Signature.MODE_SIGN);
						short sigsize=sigECDSA.sign(recvBuffer, (short)0, (short)32, buffer, BIP32_OFFSET_SIG);
						// verify sig with pubkey (x,y) & recover compression byte
						bip32_pubkey.setW(recvBuffer, BIP32_OFFSET_PUB, (short)(2*BIP32_KEY_SIZE+1)) ;
						sigECDSA.init(bip32_pubkey, Signature.MODE_VERIFY);
						boolean verify= sigECDSA.verify(recvBuffer, (short)0, (short)32, buffer, BIP32_OFFSET_SIG, sigsize);
						boolean parity= ((recvBuffer[(short)(BIP32_OFFSET_PUBY+31)]&0x01)==0);
						compbyte= (verify^parity)?(byte)0x03:(byte)0x02;
						// save compbyte in parent's object for future use
						if (parent_base==Bip32ObjectManager.NULL_OFFSET)
							bip32_master_compbyte= compbyte;
						else
							bip32_om.setByte(parent_base, (short)(BIP32_OBJECT_SIZE-1), compbyte);//bip32_mem.setByte(parent_base, (short)(BIP32_OBJECT_SIZE-1), compbyte);//debugOM
			        }
			        // compute compbyte from coord y externally (faster!)
			        if (compbyte==0x04 && (opts & 0x40)==0x40){
			        	// exit the for loop prematurely
			        	// the data returned is related to the parent with non-hardened child
			        	// we can then compute the coord-y externally
			        	// save hash of parent path (or 000...0 if masterkey)
			        	if (parent_base==Bip32ObjectManager.NULL_OFFSET){
			        		Util.arrayFillNonAtomic(buffer, (short)0, (short)32, (byte)0);
			        	}else{
							sha256.reset(); 
							sha256.doFinal(recvBuffer, BIP32_OFFSET_PATH, (short)(4*(i-1)), buffer, (byte)0);
						}
						exit_early=(short)0x8000;
			        	break; 
			        }
			    	
			        // compute HMAC of compressed pubkey + index
					recvBuffer[BIP32_OFFSET_PUB]= compbyte;
			        Util.arrayCopyNonAtomic(recvBuffer, (short)(BIP32_OFFSET_PATH+4*(i-1)), recvBuffer, BIP32_OFFSET_PUBY, (short)4);
					HmacSha512.computeHmacSha512(recvBuffer, BIP32_OFFSET_PARENT_CHAINCODE, BIP32_KEY_SIZE, recvBuffer, BIP32_OFFSET_PUB, (short)(1+BIP32_KEY_SIZE+4), recvBuffer, BIP32_OFFSET_CHILD_KEY);
				}
				else { // hardened child
					recvBuffer[BIP32_KEY_SIZE]= 0x00;
					Util.arrayCopyNonAtomic(recvBuffer, (short)(BIP32_OFFSET_PATH+4*(i-1)), recvBuffer, BIP32_OFFSET_INDEX, (short)4);
					HmacSha512.computeHmacSha512(recvBuffer, BIP32_OFFSET_PARENT_CHAINCODE, BIP32_KEY_SIZE, recvBuffer, BIP32_OFFSET_PARENT_SEPARATOR, (short)(1+BIP32_KEY_SIZE+4), recvBuffer, BIP32_OFFSET_CHILD_KEY);
				}
				
				// addition with parent_key...
				// First check that parse256(IL) < SECP256K1_R
				if(!Biginteger.lessThan(recvBuffer, BIP32_OFFSET_CHILD_KEY, Secp256k1.SECP256K1, Secp256k1.OFFSET_SECP256K1_R, BIP32_KEY_SIZE)){
					ISOException.throwIt(SW_BIP32_DERIVATION_ERROR);
				}
				// add parent_key (mod SECP256K1_R)
				if(Biginteger.add_carry(recvBuffer, BIP32_OFFSET_CHILD_KEY, recvBuffer, (short) (BIP32_KEY_SIZE+1), BIP32_KEY_SIZE)){
					// in case of final carry, we must substract SECP256K1_R
					// we have IL<SECP256K1_R and parent_key<SECP256K1_R, so IL+parent_key<2*SECP256K1_R
					Biginteger.subtract(recvBuffer, BIP32_OFFSET_CHILD_KEY, Secp256k1.SECP256K1, Secp256k1.OFFSET_SECP256K1_R, BIP32_KEY_SIZE);	
				}else{
				    // in the unlikely case where SECP256K1_R<=IL+parent_key<2^256
					if(!Biginteger.lessThan(recvBuffer, BIP32_OFFSET_CHILD_KEY, Secp256k1.SECP256K1, Secp256k1.OFFSET_SECP256K1_R, BIP32_KEY_SIZE)){
						Biginteger.subtract(recvBuffer, BIP32_OFFSET_CHILD_KEY, Secp256k1.SECP256K1, Secp256k1.OFFSET_SECP256K1_R, BIP32_KEY_SIZE);
					}
					// check that value is not 0
					if(Biginteger.equalZero(recvBuffer, BIP32_OFFSET_CHILD_KEY, BIP32_KEY_SIZE)){
						ISOException.throwIt(SW_BIP32_DERIVATION_ERROR);
					}
				}
				
				// encrypt privkey & chaincode
				aes128.init(bip32_encryptkey, Cipher.MODE_ENCRYPT);
				aes128.doFinal(recvBuffer, BIP32_OFFSET_CHILD_KEY, (short)(2*BIP32_KEY_SIZE), recvBuffer, BIP32_OFFSET_CHILD_KEY);
				
				// Update object data
				recvBuffer[BIP32_OFFSET_PUB]=0x04;
				// create object 
				// todo: should we create object for tx keys in last index (since they are usually used only once)?
				base= bip32_om.createObject(recvBuffer,BIP32_OFFSET_COLLISIONHASH);
				
			}//end if (object creation)
			
			// at this point, recvBuffer contains a copy of the object related to extended key at depth i
			// decrypt privkey & chaincode as they are encrypted at this point
			aes128.init(bip32_encryptkey, Cipher.MODE_DECRYPT);
			aes128.doFinal(recvBuffer, BIP32_OFFSET_CHILD_KEY, (short)(2*BIP32_KEY_SIZE), recvBuffer, BIP32_OFFSET_CHILD_KEY);
			// copy privkey & chain code in parent's offset
			Util.arrayCopyNonAtomic(recvBuffer, BIP32_OFFSET_CHILD_CHAINCODE, recvBuffer, BIP32_OFFSET_PARENT_CHAINCODE, BIP32_KEY_SIZE); // chaincode
			Util.arrayCopyNonAtomic(recvBuffer, BIP32_OFFSET_CHILD_KEY, recvBuffer, BIP32_OFFSET_PARENT_KEY, BIP32_KEY_SIZE); // extended_key
			recvBuffer[BIP32_KEY_SIZE]=0x00;
			
			// update parent_base for next iteration
			parent_base=base;			
		} // end for
		
		// at this point, recvBuffer contains a copy of the last extended key 
		// instantiate elliptic curve with last extended key + copy ACL
		bip32_extendedkey.setS(recvBuffer, BIP32_OFFSET_PARENT_KEY, BIP32_KEY_SIZE);
		
		if (exit_early==0x0000){
			// save chaincode to buffer, otherwise buffer already contains hash of path
			Util.arrayCopyNonAtomic(recvBuffer, (short)BIP32_OFFSET_PARENT_CHAINCODE, buffer, (short)0, BIP32_KEY_SIZE); 
		}
		// clear recvBuffer
		Util.arrayFillNonAtomic(recvBuffer, BIP32_OFFSET_PARENT_CHAINCODE, BIP32_OFFSET_END, (byte)0);
				
		// compute the corresponding partial public key...
        keyAgreement.init(bip32_extendedkey);
        short coordx_size = keyAgreement.generateSecret(Secp256k1.SECP256K1, Secp256k1.OFFSET_SECP256K1_G, (short) 65, buffer, (short)34); // compute x coordinate of public key as k*G
        Util.setShort(buffer, BIP32_KEY_SIZE, (short)(coordx_size^exit_early)); //exit_early flag signals we want to compute pubkey externaly
        
        // self-sign coordx
        sigECDSA.init(bip32_extendedkey, Signature.MODE_SIGN);
        short sign_size= sigECDSA.sign(buffer, (short)0, (short)(BIP32_KEY_SIZE+2+coordx_size), buffer, (short)(BIP32_KEY_SIZE+coordx_size+4));
        Util.setShort(buffer, (short)(BIP32_KEY_SIZE+coordx_size+2), sign_size);
        
        // coordx signed by authentikey
        sigECDSA.init(bip32_authentikey, Signature.MODE_SIGN);
        short sign_size2= sigECDSA.sign(buffer, (short)0, (short)(BIP32_KEY_SIZE+coordx_size+sign_size+4), buffer, (short)(BIP32_KEY_SIZE+coordx_size+sign_size+6));
        Util.setShort(buffer, (short)(BIP32_KEY_SIZE+coordx_size+sign_size+4), sign_size2);
        
        // return x-coordinate of public key+signatures
        // the client can recover full public-key by guessing the compression value () and verifying the signature... 
        // buffer=[chaincode(32) | coordx_size(2) | coordx | sign_size(2) | self-sign | sign_size(2) | auth_sign]
        apdu.setOutgoingAndSend((short) 0, (short)(BIP32_KEY_SIZE+coordx_size+sign_size+sign_size2+6));
        
	}// end of getBip32ExtendedKey()	
	
	/**
	 * This function allows to compute an extended pubkey externally and 
	 * store it in the secure BIP32 memory cache for future use. 
	 * This allows to speed up computation during derivation of non-hardened child.
	 * 
	 * ins: 0x74
	 * p1: 
	 * p2:
	 * data: [chaincode(32b) | coordx_size(2b) | coordx | sig_size(2b) | sig | sig_size(2b) | sig2 ]
	 * 			[ coordy_size(2b) | coordy]
	 *  returns: none
	 */
	private void setBIP32ExtendedPubkey(APDU apdu, byte[] buffer){
		// check that PIN[0] has been entered previously
		if (!pins[0].isValidated())
			ISOException.throwIt(SW_UNAUTHORIZED);
		
		// check whether the seed is initialized
		if (!bip32_seeded)
			ISOException.throwIt(SW_BIP32_UNINITIALIZED_SEED);
		
		// input 
		short bytesLeft = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
		if (bytesLeft != apdu.setIncomingAndReceive())
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);//ISOException.throwIt(bytesLeft);//
		
		short offset= (short) ISO7816.OFFSET_CDATA;
		offset+=32;
		short coordx_size= Util.getShort(buffer, offset);
		// check that the correct flag is set on msb of coordx_size
		if ((coordx_size & (short)0x8000) == (short)0x8000)
			coordx_size= (short)(coordx_size & 0x7fff);
		else
			ISOException.throwIt(SW_OPERATION_NOT_ALLOWED);
		offset+=2;
		//copy pubkey
		recvBuffer[0]=0x04;
		Util.arrayCopyNonAtomic(buffer, offset, recvBuffer, (short)1, coordx_size);
		offset+=coordx_size;
		short sig_size= Util.getShort(buffer, offset);
		offset+=2;
		short offset_sig=offset;
		offset+=sig_size;
		short authsig_size= Util.getShort(buffer, offset);
		offset+=2;
		short offset_authsig=offset;
		offset+=authsig_size;
		short coordy_size=  Util.getShort(buffer, offset);
		offset+=2;
		// copy pubkey
		Util.arrayCopyNonAtomic(buffer, offset, recvBuffer, (short)(1+coordx_size), coordy_size);
		offset+=coordy_size;
		
		// verify that authentikey signature is valid
		if (authentikey_pubkey[0]!=(byte)0x04)
			ISOException.throwIt(SW_BIP32_UNINITIALIZED_AUTHENTIKEY_PUBKEY);
		bip32_pubkey.setW(authentikey_pubkey, (short)(0), (short)(1+2*BIP32_KEY_SIZE));
		sigECDSA.init(bip32_pubkey, Signature.MODE_VERIFY);
		boolean verify= sigECDSA.verify(buffer, (short)ISO7816.OFFSET_CDATA, (short)(32+2+coordx_size+2+sig_size), buffer, offset_authsig, authsig_size);
		if (!verify)
			ISOException.throwIt(SW_SIGNATURE_INVALID);
		// verify that coordy is legit
		bip32_pubkey.setW(recvBuffer, (short)(0), (short)(1+coordx_size+coordy_size));
		sigECDSA.init(bip32_pubkey, Signature.MODE_VERIFY);
		verify= sigECDSA.verify(buffer, (short)ISO7816.OFFSET_CDATA, (short)(32+2+coordx_size), buffer, offset_sig, sig_size);
		if (!verify)
			ISOException.throwIt(SW_SIGNATURE_INVALID);
		// save compression byte from coordy
		// if hash is 00...00, compbyte relates to master key
		byte compbyte= (byte)( (recvBuffer[(short)(1+coordx_size+coordy_size-1)]&0x01)+0x02);
		if (Util.arrayCompare(buffer, (short)(ISO7816.OFFSET_CDATA+32-BIP32_ANTICOLLISION_LENGTH), bip32_om.empty, (short)0, BIP32_ANTICOLLISION_LENGTH)==0){
			bip32_master_compbyte=compbyte;
		}
		else{
			short base=bip32_om.getBaseAddress(buffer, (short)(ISO7816.OFFSET_CDATA+32-BIP32_ANTICOLLISION_LENGTH));
			if (base==Bip32ObjectManager.NULL_OFFSET)
				ISOException.throwIt(SW_OBJECT_NOT_FOUND);
			bip32_om.setByte(base, (short)(BIP32_OBJECT_SIZE-1), compbyte);
		}
		
        short pos=0;
		Util.setShort(buffer, pos, bip32_om.nb_elem_free); // number of slot available 
		pos += (short) 2;
		Util.setShort(buffer, pos, bip32_om.nb_elem_used); // number of slot used 
		pos += (short) 2;
		apdu.setOutgoingAndSend((short) 0, pos);
	}// end of setBIP32ExtendedPubkey
	
    /**
     * This function signs Bitcoin message using std or Bip32 extended key
	 *
     * ins: 0x6E
	 * p1: key number or 0xFF for the last derived Bip32 extended key 
	 * p2: Init-Update-Finalize
	 * data(init): [ full_msg_size(4b) ]
	 * data(update): [chunk_size(2b) | chunk_data]
	 * data(finalize): [chunk_size(2b) | chunk_data | (option)HMAC-2FA(20b)]
	 *  
	 * returns(init/update): none
	 * return(finalize): [sig]
	 *
     */
    private void signMessage(APDU apdu, byte[] buffer){
		// check that PIN[0] has been entered previously
		if (!pins[0].isValidated())
			ISOException.throwIt(SW_UNAUTHORIZED);
		
		byte key_nb = buffer[ISO7816.OFFSET_P1];
		if ( (key_nb!=(byte)0xFF) && ((key_nb < 0)||(key_nb >= MAX_NUM_KEYS)) )
			ISOException.throwIt(SW_INCORRECT_P1);
		
		byte p2= buffer[ISO7816.OFFSET_P2];
    	if (p2 <= (byte) 0x00 || p2 > (byte) 0x03)
			ISOException.throwIt(SW_INCORRECT_P2);
		short bytesLeft = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
		if (bytesLeft != apdu.setIncomingAndReceive())
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);	
		
    	// check whether the seed is initialized
		if (key_nb==(byte)0xFF && !bip32_seeded)
			ISOException.throwIt(SW_BIP32_UNINITIALIZED_SEED);
		
		short chunk_size, offset, recvOffset;
		switch(p2){
			// initialization
			case OP_INIT: 
				// copy message header to tmp buffer
				Util.arrayCopyNonAtomic(BITCOIN_SIGNED_MESSAGE_HEADER, (short)0, recvBuffer, (short)0, (short)BITCOIN_SIGNED_MESSAGE_HEADER.length);
				recvOffset= (short)BITCOIN_SIGNED_MESSAGE_HEADER.length;
				
				// buffer data = [4-byte msg_size]
				offset= (short)ISO7816.OFFSET_CDATA;
				recvOffset+= Biginteger.encodeVarInt(buffer, offset, recvBuffer, recvOffset);
				offset+=4;
				sha256.reset();
				sha256.update(recvBuffer, (short) 0, recvOffset);
				sign_flag= true; // set flag
				break;
			
			// update (optionnal)
			case OP_PROCESS: 
				if (!sign_flag)
					ISOException.throwIt(SW_INCORRECT_INITIALIZATION);
					
				// buffer data = [2-byte chunk_size | n-byte message to sign]
				offset= (short)ISO7816.OFFSET_CDATA;
				chunk_size=Util.getShort(buffer, offset);
				offset+=2;
				sha256.update(buffer, (short) offset, chunk_size);
				break;
			
			// final
			case OP_FINALIZE: 
				if (!sign_flag)
					ISOException.throwIt(SW_INCORRECT_INITIALIZATION);
				
				// buffer data = [2-byte chunk_size | n-byte message to sign]
				offset= (short)ISO7816.OFFSET_CDATA;
				chunk_size=Util.getShort(buffer, offset);
				offset+=2;
				bytesLeft-=2;
				sha256.doFinal(buffer, (short)offset, chunk_size, recvBuffer, (short) 0);
				sign_flag= false;// reset flag
				offset+=chunk_size;
				bytesLeft-=chunk_size;
				
				// check 2FA if required
				if(needs_2FA){
					if (bytesLeft<(short)20)
						ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
					// hmac of 64-bytes msg: (sha256(btcheader+msg) | 32bytes zero-padding)
					Util.arrayFillNonAtomic(recvBuffer, (short)32, (short)32, (byte)0x00);
					HmacSha160.computeHmacSha160(data2FA, OFFSET_2FA_HMACKEY, (short)20, recvBuffer, (short)0, (short)64, recvBuffer, (short)64);
					if (Util.arrayCompare(buffer, offset, recvBuffer, (short)64, (short)20)!=0)
						ISOException.throwIt(SW_SIGNATURE_INVALID);
				}
				
				// set key & sign
		    	if (key_nb==(byte)0xFF)
		    		sigECDSA.init(bip32_extendedkey, Signature.MODE_SIGN);
		    	else{
		    		Key key= eckeys[key_nb];
		    		// check type and size
		    		if ((key == null) || !key.isInitialized())
		    			ISOException.throwIt(SW_INCORRECT_P1);
		    		if (key.getType() != KeyBuilder.TYPE_EC_FP_PRIVATE)
		    			ISOException.throwIt(SW_INCORRECT_ALG);		
		    		if (key.getSize()!= LENGTH_EC_FP_256)
		    			ISOException.throwIt(SW_INCORRECT_ALG);
		    		sigECDSA.init(key, Signature.MODE_SIGN);
		    	}
		        short sign_size= sigECDSA.sign(recvBuffer, (short)0, (short)32, buffer, (short)0);
		        apdu.setOutgoingAndSend((short) 0, sign_size);
		    	break;
		}        		
	}
    
    /**
     * This function signs short Bitcoin message using std or Bip32 extended key in 1 APDU
	 * 
     * ins: 0x72
	 * p1: key number or 0xFF for the last derived Bip32 extended key 
	 * p2: 0x00
	 * data: [msg_size(2b) | msg_data | (option)HMAC(20b)]
	 * 
	 * return: [sig]
	 *
     */
    private void signShortMessage(APDU apdu, byte[] buffer){
		// check that PIN[0] has been entered previously
		if (!pins[0].isValidated())
			ISOException.throwIt(SW_UNAUTHORIZED);
		
		byte key_nb = buffer[ISO7816.OFFSET_P1];
		if ( (key_nb!=(byte)0xFF) && ((key_nb < 0)||(key_nb >= MAX_NUM_KEYS)) ) // debug!!
			ISOException.throwIt(SW_INCORRECT_P1);
		if (buffer[ISO7816.OFFSET_P2] != (byte) 0x00)
			ISOException.throwIt(SW_INCORRECT_P2);
		short bytesLeft = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
		if (bytesLeft != apdu.setIncomingAndReceive())
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);	
		
		// check whether the seed is initialized
		if (key_nb==(byte)0xFF && !bip32_seeded)
			ISOException.throwIt(SW_BIP32_UNINITIALIZED_SEED);
				
		// copy message header to tmp buffer
		Util.arrayCopyNonAtomic(BITCOIN_SIGNED_MESSAGE_HEADER, (short)0, recvBuffer, (short)0, (short)BITCOIN_SIGNED_MESSAGE_HEADER.length);
		short recvOffset= (short)BITCOIN_SIGNED_MESSAGE_HEADER.length;
		
		// buffer data = [2-byte size | n-byte message to sign]
		short offset= (short)ISO7816.OFFSET_CDATA;
		short msgSize= Util.getShort(buffer, offset);
		recvOffset+= Biginteger.encodeShortToVarInt(msgSize, recvBuffer, recvOffset);
		offset+=2;
		bytesLeft-=2;
		Util.arrayCopyNonAtomic(buffer, offset, recvBuffer, recvOffset, msgSize);
		offset+= msgSize;
		recvOffset+= msgSize;
		bytesLeft-= msgSize;
		
		// hash SHA-256
		sha256.reset();
		sha256.doFinal(recvBuffer, (short) 0, recvOffset, recvBuffer, (short) 0);
		
		// check 2FA if required
		if(needs_2FA){
			if (bytesLeft<(short)20)
				ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			// hmac of 64-bytes msg: (sha256(btcheader+msg) | 32bytes zero-padding)
			Util.arrayFillNonAtomic(recvBuffer, (short)32, (short)32, (byte)0x00);
			HmacSha160.computeHmacSha160(data2FA, OFFSET_2FA_HMACKEY, (short)20, recvBuffer, (short)0, (short)64, recvBuffer, (short)64);
			if (Util.arrayCompare(buffer, offset, recvBuffer, (short)64, (short)20)!=0)
				ISOException.throwIt(SW_SIGNATURE_INVALID);
		}
		
        // set key & sign
    	if (key_nb==(byte)0xFF)
    		sigECDSA.init(bip32_extendedkey, Signature.MODE_SIGN);
    	else{
    		Key key= eckeys[key_nb];
    		// check type and size
    		if ((key == null) || !key.isInitialized())
    			ISOException.throwIt(SW_INCORRECT_P1);
    		if (key.getType() != KeyBuilder.TYPE_EC_FP_PRIVATE)
    			ISOException.throwIt(SW_INCORRECT_ALG);		
    		if (key.getSize()!= LENGTH_EC_FP_256)
    			ISOException.throwIt(SW_INCORRECT_ALG);
    		sigECDSA.init(key, Signature.MODE_SIGN);
    	}
    	short sign_size= sigECDSA.sign(recvBuffer, (short)0, (short)32, buffer, (short)0);
        apdu.setOutgoingAndSend((short) 0, sign_size);
    }    
    
    /**
     * This function parses a raw transaction and returns the corresponding double SHA-256
	 * If the Bip32 seed is initialized, the hash is signed with the authentikey.
	 * 
     * ins: 0x71
	 * p1: Init or Process 
	 * p2: PARSE_STD ou PARSE_SEGWIT
	 * data: [raw_tx]
	 * 
	 * return: [hash(32b) | needs_confirm(1b) | sig_size(2b) | sig ]
	 *
	 * where:
	 * 		needs_confirm is 0x01 if a hmac-sha1 of the hash must be provided for tx signing 
     */
    private void ParseTransaction(APDU apdu, byte[] buffer){
    	// check that PIN[0] has been entered previously
		if (!pins[0].isValidated())
			ISOException.throwIt(SW_UNAUTHORIZED);
		
    	byte p1 = buffer[ISO7816.OFFSET_P1];
        byte p2 = buffer[ISO7816.OFFSET_P2];
        short dataOffset = ISO7816.OFFSET_CDATA;
        short dataRemaining = (short)(buffer[ISO7816.OFFSET_LC] & 0xff);
    	
        if (p1== OP_INIT){
        	// initialize transaction object
        	Transaction.resetTransaction();
        }
        
        // parse the transaction
        byte result = Transaction.RESULT_ERROR;
        if (p2== PARSE_STD){
        	 result= Transaction.parseTransaction(buffer, dataOffset, dataRemaining);
        }else if (p2== PARSE_SEGWIT){
        	result = Transaction.parseSegwitTransaction(buffer, dataOffset, dataRemaining);
        }
        if (result == Transaction.RESULT_ERROR) {
        	Transaction.resetTransaction();
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        else if (result == Transaction.RESULT_MORE) {
            
        	short offset = 0;
        	// Transaction context
        	Util.arrayCopyNonAtomic(Transaction.ctx, Transaction.TX_CURRENT_I, buffer, offset, Transaction.SIZEOF_U32);
        	offset += 4;
        	Util.arrayCopyNonAtomic(Transaction.ctx, Transaction.TX_CURRENT_O, buffer, offset, Transaction.SIZEOF_U32);
        	offset += 4;
        	Util.arrayCopyNonAtomic(Transaction.ctx, Transaction.TX_SCRIPT_COORD, buffer, offset, Transaction.SIZEOF_U32);
        	offset += 4;
        	Util.arrayCopyNonAtomic(Transaction.ctx, Transaction.TX_AMOUNT, buffer, offset, Transaction.SIZEOF_AMOUNT);
            offset += Transaction.SIZEOF_AMOUNT;
            
            // not so relevant context info mainly for debugging (not sensitive)
//            if (DEBUG_MODE){
//	            Util.arrayCopyNonAtomic(Transaction.ctx, Transaction.TX_I_REMAINING_I, buffer, offset, Transaction.SIZEOF_U32);
//	        	offset += 4;
//	        	Util.arrayCopyNonAtomic(Transaction.ctx, Transaction.TX_I_REMAINING_O, buffer, offset, Transaction.SIZEOF_U32);
//	        	offset += 4;
//	        	Util.arrayCopyNonAtomic(Transaction.ctx, Transaction.TX_I_SCRIPT_REMAINING, buffer, offset, Transaction.SIZEOF_U32);
//	        	offset += 4;
//	        	Util.arrayCopyNonAtomic(Transaction.ctx, Transaction.TX_TMP_BUFFER, buffer, offset, Transaction.SIZEOF_U32);
//	        	offset += Transaction.SIZEOF_AMOUNT;
//	        	Util.arrayCopyNonAtomic(Transaction.ctx, Transaction.TX_I_SCRIPT_ACTIVE, buffer, offset, Transaction.SIZEOF_U8);
//	        	offset += 1;
//	        	Util.arrayCopyNonAtomic(Transaction.ctx, Transaction.TX_B_TRANSACTION_STATE, buffer, offset, Transaction.SIZEOF_U8);
//	        	offset += 1;
//	        	Util.setShort(buffer, offset, dataOffset);
//	        	offset+=2;
//	        	Util.setShort(buffer, offset, dataRemaining);
//	        	offset+=2;
//            }
            
        	apdu.setOutgoingAndSend((short)0, offset);
        	return;
        }
        else if (result == Transaction.RESULT_FINISHED) {
            
        	// check whether 2fa is required (hmac-sha1 of tx hash)
            short need2fa=(short)0x0000;
            Util.arrayCopyNonAtomic(Transaction.ctx, Transaction.TX_AMOUNT, transactionData, OFFSET_TRANSACTION_AMOUNT, (short)8);
            Biginteger.add_carry(transactionData, OFFSET_TRANSACTION_AMOUNT, transactionData, OFFSET_TRANSACTION_TOTAL, (short)8);
            if (needs_2FA){
	            if (Biginteger.lessThan(data2FA, OFFSET_2FA_LIMIT, transactionData, OFFSET_TRANSACTION_AMOUNT, (short)8)){
	            	need2fa^= HMAC_CHALRESP_2FA; // set msb 
	            }
            }
            
        	// store transaction hash (single hash!) in memory 
            Transaction.digestFull.doFinal(transactionData, (short)0, (short)0, transactionData, OFFSET_TRANSACTION_HASH);
            // return transaction hash (double hash!) 
            // the msb bit of hash_size is set to 1 if a Hmac confirmation is required for the tx signature
            sha256.reset();
            short hash_size=sha256.doFinal(transactionData, OFFSET_TRANSACTION_HASH, (short)32, buffer, (short)2);
            Util.setShort(buffer, (short)0, (short)(hash_size+2));
            Util.setShort(buffer, (short)(2+hash_size), need2fa);
            short offset = (short)(2+hash_size+2);
        	
            // hash signed by authentikey if seed is initialized
            if (bip32_seeded){
	            sigECDSA.init(bip32_authentikey, Signature.MODE_SIGN);
	            short sign_size= sigECDSA.sign(buffer, (short)0, offset, buffer, (short)(offset+2));
	            Util.setShort(buffer, offset, sign_size);
	            offset+=(short)(2+sign_size); 
            }else{
            	Util.setShort(buffer, offset, (short)0);
            	offset+=(short)2;
            }
        	
        	// Transaction context 
            //todo: put this context in other method
        	Util.arrayCopyNonAtomic(Transaction.ctx, Transaction.TX_CURRENT_I, buffer, offset, Transaction.SIZEOF_U32);
        	offset += 4;
        	Util.arrayCopyNonAtomic(Transaction.ctx, Transaction.TX_CURRENT_O, buffer, offset, Transaction.SIZEOF_U32);
        	offset += 4;
        	Util.arrayCopyNonAtomic(Transaction.ctx, Transaction.TX_SCRIPT_COORD, buffer, offset, Transaction.SIZEOF_U32);
        	offset += 4;
        	Util.arrayCopyNonAtomic(Transaction.ctx, Transaction.TX_AMOUNT, buffer, offset, Transaction.SIZEOF_AMOUNT);
            offset += Transaction.SIZEOF_AMOUNT;
            
            // not so relevant context info mainly for debugging (not sensitive)
//            if (DEBUG_MODE){
//	            Util.arrayCopyNonAtomic(Transaction.ctx, Transaction.TX_I_REMAINING_I, buffer, offset, Transaction.SIZEOF_U32);
//	        	offset += 4;
//	        	Util.arrayCopyNonAtomic(Transaction.ctx, Transaction.TX_I_REMAINING_O, buffer, offset, Transaction.SIZEOF_U32);
//	        	offset += 4;
//	        	Util.arrayCopyNonAtomic(Transaction.ctx, Transaction.TX_I_SCRIPT_REMAINING, buffer, offset, Transaction.SIZEOF_U32);
//	        	offset += 4;
//	        	Util.arrayCopyNonAtomic(Transaction.ctx, Transaction.TX_TMP_BUFFER, buffer, offset, Transaction.SIZEOF_U32);
//	        	offset += Transaction.SIZEOF_AMOUNT;
//	        	Util.arrayCopyNonAtomic(Transaction.ctx, Transaction.TX_I_SCRIPT_ACTIVE, buffer, offset, Transaction.SIZEOF_U8);
//	        	offset += 1;
//	        	Util.arrayCopyNonAtomic(Transaction.ctx, Transaction.TX_B_TRANSACTION_STATE, buffer, offset, Transaction.SIZEOF_U8);
//	        	offset += 1;
//	        	Util.setShort(buffer, offset, dataOffset);
//	        	offset+=2;
//	        	Util.setShort(buffer, offset, dataRemaining);
//	        	offset+=2;
//            }
            
            // reset data and send result
            // buffer= [tx_hash(32) | sign_size(2) | signature | tx context(20 - 46)] //deprecated
            // buffer= [(hash_size+2)(2b) | tx_hash(32b) | need2fa(2b) | sig_size(2b) | sig(sig_size) | txcontext]
            Transaction.resetTransaction();
            apdu.setOutgoingAndSend((short)0, offset);                       
        }
        
        return;
    }
    
    /**
     * This function signs the current hash transaction with a std or the last extended key
     * The hash provided in the APDU is compared to the version stored inside the chip.
	 * Depending of the total amount in the transaction and the predefined limit, 
	 * a HMAC must be provided as an additional security layer. 
	 * 
     * ins: 0x6F
	 * p1: key number or 0xFF for the last derived Bip32 extended key  
	 * p2: 0x00
	 * data: [hash(32b) | option: 2FA-flag(2b)|hmac(20b)]
	 * 
	 * return: [sig ]
	 *
     */
    private void SignTransaction(APDU apdu, byte[] buffer){
		// check that PIN[0] has been entered previously
		if (!pins[0].isValidated())
			ISOException.throwIt(SW_UNAUTHORIZED);
		
    	byte key_nb = buffer[ISO7816.OFFSET_P1];
		if ( (key_nb!=(byte)0xFF) && ((key_nb < 0) || (key_nb >= MAX_NUM_KEYS)) )
			ISOException.throwIt(SW_INCORRECT_P1);
		
    	short bytesLeft = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
		if (bytesLeft != apdu.setIncomingAndReceive())
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		if (bytesLeft<MessageDigest.LENGTH_SHA_256)
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    	
    	// check whether the seed is initialized
		if (key_nb==(byte)0xFF && !bip32_seeded)
			ISOException.throwIt(SW_BIP32_UNINITIALIZED_SEED);
		
		// check doublehash value in buffer with cached singlehash value
		sha256.reset();
		sha256.doFinal(transactionData, OFFSET_TRANSACTION_HASH, MessageDigest.LENGTH_SHA_256, recvBuffer, (short)0);
		if ((byte)0 != Util.arrayCompare(buffer, ISO7816.OFFSET_CDATA, recvBuffer, (short)0, MessageDigest.LENGTH_SHA_256))
			ISOException.throwIt(SW_INCORRECT_TXHASH);
		
		// check challenge-response answer if necessary
		if(needs_2FA){
			if(	Biginteger.lessThan(data2FA, OFFSET_2FA_LIMIT, transactionData, OFFSET_TRANSACTION_AMOUNT, (short)8)){
				if (bytesLeft<MessageDigest.LENGTH_SHA_256+MessageDigest.LENGTH_SHA+(short)2)
					ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
				// check flag for 2fa_hmac_chalresp
				short hmac_flags= Util.getShort(buffer, (short)(ISO7816.OFFSET_CDATA+32));
				if (hmac_flags!=HMAC_CHALRESP_2FA)
					ISOException.throwIt(SW_INCORRECT_ALG);
				// hmac of 64-bytes msg: (doublesha256(raw_tx) | 32bytes zero-padding)
				Util.arrayFillNonAtomic(recvBuffer, (short)32, (short)32, (byte)0x00);
				HmacSha160.computeHmacSha160(data2FA, OFFSET_2FA_HMACKEY, (short)20, recvBuffer, (short)0, (short)64, recvBuffer, (short)64);
				if (Util.arrayCompare(buffer, (short)(ISO7816.OFFSET_CDATA+32+2), recvBuffer, (short)64, (short)20)!=0)
					ISOException.throwIt(SW_SIGNATURE_INVALID);
				// reset total amount
				Util.arrayFillNonAtomic(transactionData, OFFSET_TRANSACTION_TOTAL, (short)8, (byte)0x00);
			}
			else{					
				//update total amount
				Util.arrayCopyNonAtomic(transactionData, OFFSET_TRANSACTION_AMOUNT, transactionData, OFFSET_TRANSACTION_TOTAL, (short)8);
			}
		}
		
		// hash+sign singlehash
    	if (key_nb==(byte)0xFF)
    		sigECDSA.init(bip32_extendedkey, Signature.MODE_SIGN);
    	else{
    		Key key= eckeys[key_nb];
    		// check type and size
    		if ((key == null) || !key.isInitialized())
    			ISOException.throwIt(SW_INCORRECT_P1);
    		if (key.getType() != KeyBuilder.TYPE_EC_FP_PRIVATE)
    			ISOException.throwIt(SW_INCORRECT_ALG);		
    		if (key.getSize()!= LENGTH_EC_FP_256)
    			ISOException.throwIt(SW_INCORRECT_ALG);
    		sigECDSA.init(key, Signature.MODE_SIGN);
    	}
        short sign_size= sigECDSA.sign(transactionData, OFFSET_TRANSACTION_HASH, (short)32, buffer, (short)0);
        apdu.setOutgoingAndSend((short) 0, sign_size);
    	
    }
    
    /**
	 * This function allows to set the 2FA key and enable 2FA.
	 * Once activated, 2FA can only be deactivated when the seed is reset.
	 *  
	 *  ins: 0x79
	 *  p1: 0x00
	 *  p2: 0x00
	 *  data: [hmacsha1_key(20b) | amount_limit(8b)]
	 *  return: (none)
	 */
	private void set2FAKey(APDU apdu, byte[] buffer){
		// check that PIN[0] has been entered previously
		if (!pins[0].isValidated())
			ISOException.throwIt(SW_UNAUTHORIZED);
		
		if (needs_2FA)
			ISOException.throwIt(SW_2FA_INITIALIZED_KEY);
		
		if (!done_once_2FA){
			data2FA= new byte[OFFSET_2FA_SIZE];
			randomData = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
	        aes128_cbc= Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
	        key_2FA= (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
	        done_once_2FA= true;
		}
		
		short offset= ISO7816.OFFSET_CDATA;
		Util.arrayCopyNonAtomic(buffer, offset, data2FA, OFFSET_2FA_HMACKEY, (short)20); 
		offset+=(short)20;
		Util.arrayCopyNonAtomic(buffer, offset, data2FA, OFFSET_2FA_LIMIT, (short)8); 
		offset+=(short)8;
		// hmac derivation for id_2FA & key_2FA
		HmacSha160.computeHmacSha160(data2FA, OFFSET_2FA_HMACKEY, (short)20, CST_2FA, (short)0, (short)6, data2FA, OFFSET_2FA_ID);
        HmacSha160.computeHmacSha160(data2FA, OFFSET_2FA_HMACKEY, (short)20, CST_2FA, (short)6, (short)7, recvBuffer, (short)0);
        key_2FA.setKey(recvBuffer,(short)0); // AES-128: 16-bytes key!!
        // 2FA counter for seed_reset()
        Util.arrayFillNonAtomic(data2FA, OFFSET_2FA_COUNTER, (short)4,(byte)0);
        needs_2FA= true;		
	}
    
	/**
	 * This function returns the counter_2FA byte array that is stored by the Satochip.
	 * This counter is increased each time the card verify a 2FA response for a challenge 
	 * based on this counter.
	 *  
	 *  ins: 0x78
	 *  p1: 0x00
	 *  p2: 0x00
	 *  data: (none)
	 *  return: [counter_2FA (4b)]
	 */
	private void getCounter2FA(APDU apdu, byte[] buffer){
		// check that PIN[0] has been entered previously
		if (!pins[0].isValidated())
			ISOException.throwIt(SW_UNAUTHORIZED);
		
		// check that 2FA is enabled
		if (!needs_2FA)
			ISOException.throwIt(SW_2FA_UNINITIALIZED_KEY);
		
		Util.arrayCopyNonAtomic(data2FA, OFFSET_2FA_COUNTER, buffer, (short)0, (short)4);
		apdu.setOutgoingAndSend((short) 0, (short)4);
	}
    
    /**
     * This function encrypts/decrypt a given message with a 16bytes secret key derived from the 2FA key.
     * It also returns an id derived from the 2FA key.
     * This is used to privately exchange tx data between the hw wallet and the 2FA device.
	 * 
     * Algorithms: 
     *      id_2FA is hmac-sha1(secret_2FA, "id_2FA"), 
     *      key_2FA is hmac-sha1(secret_2FA, "key_2FA"), 
     *      message encrypted using AES
     *
     * ins: 0x76
	 * p1: 0x00 for encryption, 0x01 for decryption  
	 * p2: Init-Update-Finalize
	 * data(init): IF_ENCRYPT: none ELSE: [IV(16b)]
     * data(update/finalize): [chunk_size(2b) | chunk_data]
	 * 
	 * return(init): IF_ENCRYPT:[IV(16b) | id_2FA(20b)] ELSE: none
     * return(update/finalize): [chunk_size(2b) | chunk_data]
	 * 
	 *
     */
    private void CryptTransaction2FA(APDU apdu, byte[] buffer){
        // check that PIN[0] has been entered previously
    	if (!pins[0].isValidated())
			ISOException.throwIt(SW_UNAUTHORIZED);
        
    	// check that 2FA is enabled
		if (!needs_2FA)
			ISOException.throwIt(SW_2FA_UNINITIALIZED_KEY);
    	
        byte ciph_dir = buffer[ISO7816.OFFSET_P1];
        byte ciph_op = buffer[ISO7816.OFFSET_P2];
        short bytesLeft = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
        short dataOffset = ISO7816.OFFSET_CDATA;
        
        short IVlength=(short)16;
        switch(ciph_op){
            case OP_INIT:
                if (ciph_dir!=Cipher.MODE_ENCRYPT &&  ciph_dir!=Cipher.MODE_DECRYPT )
                    ISOException.throwIt(SW_INVALID_PARAMETER);
                
                if (ciph_dir==Cipher.MODE_ENCRYPT){
                    randomData.generateData(buffer,(short)0, IVlength);
                    aes128_cbc.init(key_2FA, Cipher.MODE_ENCRYPT, buffer, (short)0, IVlength);
                    Util.arrayCopyNonAtomic(data2FA, OFFSET_2FA_ID, buffer, (short)IVlength, (short)20);
                    apdu.setOutgoingAndSend((short) 0, (short)(IVlength + 20));
                }
                if (ciph_dir==Cipher.MODE_DECRYPT){
                    aes128_cbc.init(key_2FA, Cipher.MODE_DECRYPT, buffer, dataOffset, IVlength);
                }
                break;
            case OP_PROCESS:
            case OP_FINALIZE:
                if (bytesLeft < 2)
                    ISOException.throwIt(SW_INVALID_PARAMETER);
                short size = Util.getShort(buffer, dataOffset);
                if (bytesLeft < (short) (2 + size))
                    ISOException.throwIt(SW_INVALID_PARAMETER);
                
                short sizeout=0;
                if (ciph_op == OP_PROCESS)
                    sizeout=aes128_cbc.update(buffer, (short) (dataOffset + 2), size, buffer, (short) 2);
                else // ciph_op == OP_FINALIZE
                    sizeout=aes128_cbc.doFinal(buffer, (short) (dataOffset + 2), size, buffer, (short) 2);
                // Also copies the Short size information
                Util.setShort(buffer,(short)0,  sizeout);
                apdu.setOutgoingAndSend((short) 0, (short) (sizeout + 2));
                break;
            default:
                ISOException.throwIt(SW_INCORRECT_P2);    
        }   
    }
    
    
    // For debug purpose only
    
//  private void setBIP32ExtendedKey(APDU apdu, byte[] buffer){
//  	
//  	// set default private point
//      byte[] key_data={
//              (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
//              (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x01 
//      }; 
//      bip32_extendedkey.setS(key_data, (short)0, BIP32_KEY_SIZE); 
//      
//      // compute the corresponding partial public key...
//      keyAgreement.init(bip32_extendedkey);
//      short coordx_size = keyAgreement.generateSecret(SECP256K1_G, (short) 0, (short) SECP256K1_G.length, buffer, (short)2); // compute x coordinate of public key as k*G
//      Util.setShort(buffer, (short)0, coordx_size);
//      
//      // sign fixed message
//      sigECDSA.init(bip32_extendedkey, Signature.MODE_SIGN);
//      short sign_size= sigECDSA.sign(buffer, (short)0, (short)(coordx_size+2), buffer, (short)(coordx_size+4));
//      Util.setShort(buffer, (short)(coordx_size+2), sign_size);
//      
//      // return x-coordinate of public key+signature
//      // the client can recover full public-key from the signature or
//      // by guessing the compression value () and verifying the signature... 
//      apdu.setOutgoingAndSend((short) 0, (short)(coordx_size+sign_size+4));
//      
//  }    
    
//	private void computeHmac(APDU apdu, byte[] buffer) {
//		if (buffer[ISO7816.OFFSET_P1] != (byte)20 && buffer[ISO7816.OFFSET_P1] != (byte)64)
//			ISOException.throwIt(SW_INCORRECT_P1);
//		if (buffer[ISO7816.OFFSET_P2] != (byte) 0x00)
//			ISOException.throwIt(SW_INCORRECT_P2);
//		short avail = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
//		if (apdu.setIncomingAndReceive() != avail)
//			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
//		
//		short pos= ISO7816.OFFSET_CDATA;//apdu.getOffsetCdata(); //(short) ISO7816.OFFSET_CDATA;
//		short key_size=Util.getShort(buffer, pos);
//		pos+=2;
//		pos+=key_size;
//		short msg_size=Util.getShort(buffer, pos);
//		pos+=2;
//		short hashSize=0;
//		if (buffer[ISO7816.OFFSET_P1]==(byte)20)
//			hashSize= HmacSha160.computeHmacSha160(buffer, (short)(ISO7816.OFFSET_CDATA+2), key_size, buffer, pos, msg_size, buffer, (short)0);
//		else if (buffer[ISO7816.OFFSET_P1]==(byte)64)
//			hashSize= HmacSha512.computeHmacSha512(buffer, (short)(ISO7816.OFFSET_CDATA+2), key_size, buffer, pos, msg_size, buffer, (short)0);
//		apdu.setOutgoingAndSend((short) 0, hashSize);
//		return;
//	}
	
//	private void computeSha512(APDU apdu, byte[] buffer) {
//		if (buffer[ISO7816.OFFSET_P1] != (byte) 0x00)
//			ISOException.throwIt(SW_INCORRECT_P1);
//		if (buffer[ISO7816.OFFSET_P2] != (byte) 0x00)
//			ISOException.throwIt(SW_INCORRECT_P2);
//		short avail2 = apdu.setIncomingAndReceive();
//	
//		sha512.reset();
//		//sha512.doFinal(data, (short) 0, avail2, buffer, (short)0);
//		sha512.doFinal(buffer, (short) ISO7816.OFFSET_CDATA, avail2, buffer, (short)0);
//	
//		apdu.setOutgoingAndSend((short) 0, Sha2.SHA512_DIGEST_LENGTH);
// 	}

//    private void testSha512(APDU apdu, byte[] buffer){
//		byte p1= buffer[ISO7816.OFFSET_P1];
//		switch(p1){
//			// add_carry
//			case 0x00:
//				Sha512.test_add_carry(buffer, (short)ISO7816.OFFSET_CDATA, buffer, (short)(ISO7816.OFFSET_CDATA+8));
//				break;
//			case 0x01:
//				Sha512.test_add_carry_fast(buffer, (short)ISO7816.OFFSET_CDATA, buffer, (short)(ISO7816.OFFSET_CDATA+8));
//				break;
//			case 0x02:
//				Sha512.test_add_carry_fast2(buffer, (short)ISO7816.OFFSET_CDATA, buffer, (short)(ISO7816.OFFSET_CDATA+8));
//				break;
//			case 0x03:
//				Sha512.test_add_carry_fast3(buffer, (short)ISO7816.OFFSET_CDATA, buffer, (short)(ISO7816.OFFSET_CDATA+8));
//				break;
//			// Ch	
//			case 0x04:					
//				Sha512.test_Ch(buffer, (short)ISO7816.OFFSET_CDATA, buffer, (short)(ISO7816.OFFSET_CDATA+8), buffer, (short)(ISO7816.OFFSET_CDATA+16), buffer, (short)(ISO7816.OFFSET_CDATA+24));
//				break;
//			case 0x05:					
//				Sha512.test_Ch_fast(buffer, (short)ISO7816.OFFSET_CDATA, buffer, (short)(ISO7816.OFFSET_CDATA+8), buffer, (short)(ISO7816.OFFSET_CDATA+16), buffer, (short)(ISO7816.OFFSET_CDATA+24));
//				break;
//			// Maj	
//			case 0x06:					
//				Sha512.test_Maj(buffer, (short)ISO7816.OFFSET_CDATA, buffer, (short)(ISO7816.OFFSET_CDATA+8), buffer, (short)(ISO7816.OFFSET_CDATA+16), buffer, (short)(ISO7816.OFFSET_CDATA+24));
//				break;
//			case 0x07:					
//				Sha512.test_Maj_fast(buffer, (short)ISO7816.OFFSET_CDATA, buffer, (short)(ISO7816.OFFSET_CDATA+8), buffer, (short)(ISO7816.OFFSET_CDATA+16), buffer, (short)(ISO7816.OFFSET_CDATA+24));
//				break;	
//			// E0-E1-Sig0-Sig1	
//			case 0x10:					
//				Sha512.test_E0_opt(buffer, (short)ISO7816.OFFSET_CDATA, buffer, (short)(ISO7816.OFFSET_CDATA+8));
//				break;
//			case 0x11:					
//				Sha512.test_E0_fast(buffer, (short)ISO7816.OFFSET_CDATA, buffer, (short)(ISO7816.OFFSET_CDATA+8));
//				break;	
//			case 0x12:					
//				Sha512.test_E1_opt(buffer, (short)ISO7816.OFFSET_CDATA, buffer, (short)(ISO7816.OFFSET_CDATA+8));
//				break;
//			case 0x13:					
//				Sha512.test_E1_fast(buffer, (short)ISO7816.OFFSET_CDATA, buffer, (short)(ISO7816.OFFSET_CDATA+8));
//				break;	
//			case 0x14:					
//				Sha512.test_Sig0_opt(buffer, (short)ISO7816.OFFSET_CDATA, buffer, (short)(ISO7816.OFFSET_CDATA+8));
//				break;
//			case 0x15:					
//				Sha512.test_Sig0_fast(buffer, (short)ISO7816.OFFSET_CDATA, buffer, (short)(ISO7816.OFFSET_CDATA+8));
//				break;	
//			case 0x16:					
//				Sha512.test_Sig1_opt(buffer, (short)ISO7816.OFFSET_CDATA, buffer, (short)(ISO7816.OFFSET_CDATA+8));
//				break;
//			case 0x17:					
//				Sha512.test_Sig1_fast(buffer, (short)ISO7816.OFFSET_CDATA, buffer, (short)(ISO7816.OFFSET_CDATA+8));
//				break;	
//			case 0x20:					
//				Sha512.test_updateW(buffer, ISO7816.OFFSET_CDATA, buffer[ISO7816.OFFSET_P2]);
//				break;
//			case 0x21:					
//				Sha512.test_updateW_fast(buffer, ISO7816.OFFSET_CDATA, buffer[ISO7816.OFFSET_P2]);
//		}
//		apdu.setOutgoingAndSend((short) 0, (short)(128));
//    }
    
} // end of class JAVA_APPLET

