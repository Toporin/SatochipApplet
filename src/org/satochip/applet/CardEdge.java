/*
 * SatoChip Bitcoin Hardware Wallet based on javacard
 * (c) 2015 by Toporin - 16DMCk4WUaHofchAhpMaQS4UPm4urcy2dN
 * Sources available on https://github.com/Toporin					 
 * Changes include: -partial support for Bip32 (only hardened keys)
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
 * Copyright (C) 2015 Toporin 
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * Changes to this license can be made only by the copyright author with
 * explicit written consent.
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
 * Alternatively, the contents of this file may be used under the terms of
 * the GNU Lesser General Public License Version 2.1 (the "LGPL"), in which
 * case the provisions of the LGPL are applicable instead of those above. If
 * you wish to allow use of your version of this file only under the terms
 * of the LGPL, and not to allow others to use your version of this file
 * under the terms of the BSD license, indicate your decision by deleting
 * the provisions above and replace them with the notice and other
 * provisions required by the LGPL. If you do not delete the provisions
 * above, a recipient may use your version of this file under the terms of
 * either the BSD license or the LGPL.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 * END LICENSE_BLOCK 
 * 
 */

package org.satochip.applet;

import javacard.framework.APDU;
import javacard.framework.CardRuntimeException;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN;
import javacard.framework.SystemException;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.DESKey;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
//import javacard.security.HMACKey;
import javacard.security.Key;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.RSAPrivateCrtKey;
import javacard.security.RSAPrivateKey;
import javacard.security.RSAPublicKey;
import javacard.security.RandomData;
import javacard.security.Signature;
import javacard.security.MessageDigest;
import javacardx.apdu.ExtendedLength; //debugXL
import javacardx.crypto.Cipher;

/**
 * Implements MUSCLE's Card Edge Specification.
 * <p>
 * 
 * TODO:
 * <ul>
 * <li>Allows maximum number of keys and PINs and total mem to be specified at
 * the instantiation moment.
 * <p>
 * <li>How do transactions fit in the methods ?
 * <li>Where should we issue begin/end transaction ?
 * <li>Should we ever abort transaction ? Where ?
 * <li>Every time there is an "if (avail < )" check, call ThrowDeleteObjects().
 * </ul>
 */
public class CardEdge extends javacard.framework.Applet implements ExtendedLength { 

	/* constants declaration */
	
	/** 
	 * VERSION HISTORY
	 * PROTOCOL VERSION: changes that impact compatibility with the client side
	 * APPLET VERSION:   changes with no impact on compatibility of the client
	 */
	// 0.1-0.1: initial version
	// 0.2-0.1: support for hmac-sha1 authorization + improved sha256 + bip32 full suport  
	// 0.3-0.1: change parseTransaction response for coherence: add separate short flags for second factor authentication  
	// 0.3-0.2: fast Sha512 computation   
	private final static byte PROTOCOL_MAJOR_VERSION = (byte) 0; 
	private final static byte PROTOCOL_MINOR_VERSION = (byte) 3;
	private final static byte APPLET_MAJOR_VERSION = (byte) 0;
	private final static byte APPLET_MINOR_VERSION = (byte) 2;
	
	// Maximum number of keys handled by the Cardlet
	private final static byte MAX_NUM_KEYS = (byte) 16;
	// Maximum number of PIN codes
	private final static byte MAX_NUM_PINS = (byte) 8;
	// Maximum number of keys allowed for ExtAuth
	//private final static byte MAX_NUM_AUTH_KEYS = (byte) 6;

	// Maximum size for the extended APDU buffer for a 2048 bit key:
	// CLA [1 byte] + INS [1 byte] + P1 [1 byte] + P2 [1 byte] +
	// LC [3 bytes] + cipher_mode[1 byte] + cipher_direction [1 byte] +
	// data_location [1 byte] + data_size [2 bytes] + data [256 bytes]
	// = 268 bytes
	private final static short EXT_APDU_BUFFER_SIZE = (short) 268;
	private final static short TMP_BUFFER_SIZE = (short) 256;

	// Minimum PIN size
	private final static byte PIN_MIN_SIZE = (byte) 4;
	// Maximum PIN size
	private final static byte PIN_MAX_SIZE = (byte) 16;
	// PIN[0] initial value...
	private final static byte[] PIN_INIT_VALUE={(byte)'M',(byte)'u',(byte)'s',(byte)'c',(byte)'l',(byte)'e',(byte)'0',(byte)'0'};
	
	// Maximum external authentication tries per key
	private final static byte MAX_KEY_TRIES = (byte) 5;

	// Import/Export Object ID
	private final static short IN_OBJECT_CLA = (short) 0xFFFF;
	private final static short IN_OBJECT_ID = (short) 0xFFFE;
	private final static short OUT_OBJECT_CLA = (short) 0xFFFF;
	private final static short OUT_OBJECT_ID = (short) 0xFFFF;

	private final static byte KEY_ACL_SIZE = (byte) 6;
	private final static byte ACL_READ = (byte) 0;
	private final static byte ACL_WRITE = (byte) 2;
	private final static byte ACL_USE = (byte) 4;
	
	// Standard public ACL
	private static byte[] STD_PUBLIC_ACL;/*
										 * = { 0x0000, // Read always allowed
										 * 0x0000, // Write always allowed
										 * 0x0000 // Delete always allowed };
										 */
	private static byte[] acl; // Temporary ACL

	// code of CLA byte in the command APDU header
	private final static byte CardEdge_CLA = (byte) 0xB0;

	/****************************************
	 * Instruction codes *
	 ****************************************/

	// Applet initialization
	private final static byte INS_SETUP = (byte) 0x2A;

	// Keys' use and management
	private final static byte INS_GEN_KEYPAIR = (byte) 0x30;
	private final static byte INS_GEN_KEYSYM = (byte) 0x31;
	private final static byte INS_IMPORT_KEY = (byte) 0x32;
	//private final static byte INS_EXPORT_KEY = (byte) 0x34;
	private final static byte INS_GET_PUBLIC_FROM_PRIVATE= (byte)0x35;
	private final static byte INS_COMPUTE_CRYPT = (byte) 0x36;
	private final static byte INS_COMPUTE_SIGN = (byte) 0x37; // added
	
	// External authentication
	private final static byte INS_CREATE_PIN = (byte) 0x40;
	private final static byte INS_VERIFY_PIN = (byte) 0x42;
	private final static byte INS_CHANGE_PIN = (byte) 0x44;
	private final static byte INS_UNBLOCK_PIN = (byte) 0x46;
	private final static byte INS_LOGOUT_ALL = (byte) 0x60;
	//private final static byte INS_GET_CHALLENGE = (byte) 0x62;
	//private final static byte INS_EXT_AUTH = (byte) 0x38;

	// Objects' use and management
	private final static byte INS_CREATE_OBJ = (byte) 0x5A;
	private final static byte INS_DELETE_OBJ = (byte) 0x52;
	private final static byte INS_READ_OBJ = (byte) 0x56;
	private final static byte INS_WRITE_OBJ = (byte) 0x54;
	private final static byte INS_SIZE_OBJ = (byte) 0x57;

	// Status information
	private final static byte INS_LIST_OBJECTS = (byte) 0x58;
	private final static byte INS_LIST_PINS = (byte) 0x48;
	private final static byte INS_LIST_KEYS = (byte) 0x3A;
	private final static byte INS_GET_STATUS = (byte) 0x3C;
	
	// HD wallet
	private final static byte INS_COMPUTE_SHA512 = (byte) 0x6A;
	//private final static byte INS_COMPUTE_HMACSHA512= (byte) 0x6B;
	private final static byte INS_COMPUTE_HMAC= (byte) 0x6B;
	private final static byte INS_BIP32_IMPORT_SEED= (byte) 0x6C;
	private final static byte INS_BIP32_GET_AUTHENTIKEY= (byte) 0x73;
	private final static byte INS_BIP32_GET_EXTENDED_KEY= (byte) 0x6D;
	private final static byte INS_BIP32_SET_EXTENDED_KEY= (byte) 0x70;
	private final static byte INS_SIGN_MESSAGE= (byte) 0x6E;
	private final static byte INS_SIGN_SHORT_MESSAGE= (byte) 0x72;
	private final static byte INS_SIGN_TRANSACTION= (byte) 0x6F;
	private final static byte INS_PARSE_TRANSACTION = (byte) 0x71;
	// debug
	private final static byte INS_TEST_SHA1 = (byte) 0x80;
	

	/** There have been memory problems on the card */
	private final static short SW_NO_MEMORY_LEFT = ObjectManager.SW_NO_MEMORY_LEFT;
	/** Entered PIN is not correct */
	private final static short SW_AUTH_FAILED = (short) 0x9C02;
	/** Required operation is not allowed in actual circumstances */
	private final static short SW_OPERATION_NOT_ALLOWED = (short) 0x9C03;
	/** Required setup is not not done */
	private final static short SW_SETUP_NOT_DONE = (short) 0x9C04;
	/** Required feature is not (yet) supported */
	private final static short SW_UNSUPPORTED_FEATURE = (short) 0x9C05;
	/** Required operation was not authorized because of a lack of privileges */
	private final static short SW_UNAUTHORIZED = (short) 0x9C06;
	/** Required object is missing */
	private final static short SW_OBJECT_NOT_FOUND = (short) 0x9C07;
	/** New object ID already in use */
	private final static short SW_OBJECT_EXISTS = (short) 0x9C08;
	/** Algorithm specified is not correct */
	private final static short SW_INCORRECT_ALG = (short) 0x9C09;

	/** Incorrect P1 parameter */
	private final static short SW_INCORRECT_P1 = (short) 0x9C10;
	/** Incorrect P2 parameter */
	private final static short SW_INCORRECT_P2 = (short) 0x9C11;
	/** No more data available */
	private final static short SW_SEQUENCE_END = (short) 0x9C12;
	/** Invalid input parameter to command */
	private final static short SW_INVALID_PARAMETER = (short) 0x9C0F;

	/** Verify operation detected an invalid signature */
	private final static short SW_SIGNATURE_INVALID = (short) 0x9C0B;
	/** Operation has been blocked for security reason */
	private final static short SW_IDENTITY_BLOCKED = (short) 0x9C0C;
	/** Unspecified error */
	private final static short SW_UNSPECIFIED_ERROR = (short) 0x9C0D;
	/** For debugging purposes */
	private final static short SW_INTERNAL_ERROR = (short) 0x9CFF;
	/** For debugging purposes 2*/
	private final static short SW_DEBUG_FLAG = (short) 0x9FFF;
	/** Very low probability error */
	private final static short SW_BIP32_DERIVATION_ERROR = (short) 0x9C0E;
	/** Support only hardened key currently */
	private final static short SW_BIP32_HARDENED_KEY_ERROR = (short) 0x9C16;
	/** Incorrect initialization of method */
	private final static short SW_INCORRECT_INITIALIZATION = (short) 0x9C13;
	/** Bip32 seed is not initialized*/
	private final static short SW_BIP32_UNINITIALIZED_SEED = (short) 0x9C14;
	/** Incorrect transaction hash */
	private final static short SW_INCORRECT_TXHASH = (short) 0x9C15;
	
	// KeyBlob Encoding in Key Blobs
	private final static byte BLOB_ENC_PLAIN = (byte) 0x00;

	// Cipher Operations admitted in ComputeCrypt()
	private final static byte OP_INIT = (byte) 0x01;
	private final static byte OP_PROCESS = (byte) 0x02;
	private final static byte OP_FINALIZE = (byte) 0x03;

	// Cipher Modes admitted in ComputeCrypt()
	private final static byte DL_APDU = (byte) 0x01;
	private final static byte DL_OBJECT = (byte) 0x02;
	private final static byte LIST_OPT_RESET = (byte) 0x00;
	private final static byte LIST_OPT_NEXT = (byte) 0x01;

	private final static byte OPT_DEFAULT = (byte) 0x00; // Use JC defaults
	private final static byte OPT_RSA_PUB_EXP = (byte) 0x01; // RSA: provide public exponent
    private final static byte OPT_EC_SECP256k1 = (byte) 0x03; // EC: provide P, a, b, G, R, K public key parameters 
        
	// Offsets in buffer[] for key generation
	private final static short OFFSET_GENKEY_ALG = (short) (ISO7816.OFFSET_CDATA);
	private final static short OFFSET_GENKEY_SIZE = (short) (ISO7816.OFFSET_CDATA + 1);
	private final static short OFFSET_GENKEY_PRV_ACL = (short) (ISO7816.OFFSET_CDATA + 3);
	private final static short OFFSET_GENKEY_PUB_ACL = (short) (OFFSET_GENKEY_PRV_ACL + KEY_ACL_SIZE);
	private final static short OFFSET_GENKEY_OPTIONS = (short) (OFFSET_GENKEY_PUB_ACL + KEY_ACL_SIZE);
	private final static short OFFSET_GENKEY_RSA_PUB_EXP_LENGTH = (short) (OFFSET_GENKEY_OPTIONS + 1);
	private final static short OFFSET_GENKEY_RSA_PUB_EXP_VALUE = (short) (OFFSET_GENKEY_RSA_PUB_EXP_LENGTH + 2);

	// JC API 2.2.2 does not define these constants:
	private final static byte ALG_ECDSA_SHA_256= (byte) 33;
	private final static byte ALG_EC_SVDP_DH_PLAIN= (byte) 3; //https://javacard.kenai.com/javadocs/connected/javacard/security/KeyAgreement.html#ALG_EC_SVDP_DH_PLAIN
	private final static short LENGTH_EC_FP_256= (short) 256;
		
	/****************************************
	 * Instance variables declaration *
	 ****************************************/

	// Memory & Object Manager
	private MemoryManager mem;
	private ObjectManager om;
	
	// Key objects (allocated on demand)
	private Key[] keys;
	// Key ACLs
	private byte[] keyACLs;
	// Key Tries Left
	private byte[] keyTries;
	// Key iterator for ListKeys: it's an offset in the keys[] array.
	private byte key_it;
	// True if a GetChallenge() has been issued
	//private boolean getChallengeDone;

	/*
	 * KeyPair, Cipher and Signature objects * These are allocated on demand *
	 * TODO: Here we could have just 1 Object[] and * make proper casts when
	 * needed
	 */
	private Cipher[] ciphers;
	private Signature[] signatures;
	// Says if we are using a signature or a cipher object
	private byte[] ciph_dirs;
	private KeyPair[] keyPairs;
	
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
	private byte create_object_ACL;
	private byte create_key_ACL;
	private byte create_pin_ACL;
	
	// shared cryptographic objects
	private RandomData randomData;
	private KeyAgreement keyAgreement;
	private Signature sigECDSA;
	private Cipher aes128;
	
	/*********************************************
	 *  BIP32 Hierarchical Deterministic Wallet  *
	 *********************************************/
	// Secure Memory & Object Manager with no access from outside (used internally for storing BIP32 objects)
	private MemoryManager bip32_mem;
	private ObjectManager bip32_om;
	
	// seed derivation
	private static final byte[] BITCOIN_SEED = {'B','i','t','c','o','i','n',' ','s','e','e','d'};
	private static final byte[] BITCOIN_SEED2 = {'B','i','t','c','o','i','n',' ','s','e','e','d','2'};
	private static final byte MAX_BIP32_DEPTH = 10; // max depth in extended key from master (m/i is depth 1)
	
	// BIP32_object= [ hash(address) (4b) | extended_key (32b) | chain_code (32b) | compression_byte(1b)]
	// recvBuffer=[ parent_chain_code (32b) | 0x00 | parent_key (32b) | hash(address) (32b) | current_extended_key(32b) | current_chain_code(32b) ]
	// hash(address)= [ index(4b) | unused (16b) | ANTICOLLISIONHASHTMP(4b)| crc (4b) | ANTICOLLISIONHASH(4b)]
	private static final short BIP32_KEY_SIZE= 32; // size of extended key and chain code is 256 bits
	private static final short BIP32_ANTICOLLISION_LENGTH=4; // max 12 bytes so that index+crc + two hashes fit in 32 bits
	private static final short BIP32_OBJECT_SIZE= (short)(2*BIP32_KEY_SIZE+BIP32_ANTICOLLISION_LENGTH+1);  
	
	// offset in working buffer
	private static final short BIP32_OFFSET_PARENT_CHAINCODE=0;
	private static final short BIP32_OFFSET_PARENT_SEPARATOR=BIP32_KEY_SIZE;
	private static final short BIP32_OFFSET_PARENT_KEY=BIP32_KEY_SIZE+1;
	private static final short BIP32_OFFSET_INDEX= (short)(2*BIP32_KEY_SIZE+1); // offset in recvBuffer
	private static final short BIP32_OFFSET_COLLISIONHASHTMP= (short)(BIP32_OFFSET_INDEX+BIP32_KEY_SIZE-2*BIP32_ANTICOLLISION_LENGTH-4);
	private static final short BIP32_OFFSET_CRC= (short)(BIP32_OFFSET_INDEX+BIP32_KEY_SIZE-BIP32_ANTICOLLISION_LENGTH-4);
	private static final short BIP32_OFFSET_COLLISIONHASH= (short)(BIP32_OFFSET_INDEX+BIP32_KEY_SIZE-BIP32_ANTICOLLISION_LENGTH);
	private static final short BIP32_OFFSET_CHILD_KEY= (short)(BIP32_OFFSET_INDEX+BIP32_KEY_SIZE); 
	private static final short BIP32_OFFSET_CHILD_CHAINCODE= (short)(BIP32_OFFSET_CHILD_KEY+BIP32_KEY_SIZE);
	private static final short BIP32_OFFSET_PUB= (short)(BIP32_OFFSET_CHILD_CHAINCODE+BIP32_KEY_SIZE);
	private static final short BIP32_OFFSET_PUBX= (short)(BIP32_OFFSET_PUB+1);
	private static final short BIP32_OFFSET_PUBY= (short)(BIP32_OFFSET_PUBX+BIP32_KEY_SIZE);
	private static final short BIP32_OFFSET_PATH= (short)(BIP32_OFFSET_PUBY+BIP32_KEY_SIZE);
	private static final short BIP32_OFFSET_END= (short)(BIP32_OFFSET_PATH+4*MAX_BIP32_DEPTH);
	private static final short BIP32_OFFSET_SIG= (short)(ISO7816.OFFSET_CDATA+4*MAX_BIP32_DEPTH);
	
	//   bip32 keys
	private boolean bip32_seeded= false;
	private byte[] bip32_masterACL; // define right access for Write,Read, and Use
	private byte[] bip32_extendedACL; // define right access for Write,Read, and Use
	private byte bip32_master_compbyte; // compression byte for master key
	private AESKey bip32_masterkey; 
	private AESKey bip32_masterchaincode; 
	private AESKey bip32_encryptkey; // used to encrypt sensitive data in object
	private ECPrivateKey bip32_extendedkey; // object storing last extended key used
	private ECPrivateKey bip32_authentikey; // key used to authenticate data
	private ECPublicKey bip32_pubkey;
	
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
	private static final byte OFFSET_TRANSACTION_LIMIT=OFFSET_TRANSACTION_TOTAL+8;
	private static final byte OFFSET_TRANSACTION_HMACKEY=OFFSET_TRANSACTION_LIMIT+8;
	private static final byte OFFSET_TRANSACTION_SIZE=OFFSET_TRANSACTION_HMACKEY+20;
	private static final short HMAC_CHALRESP_2FA=(short)0x8000;
	
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
//		// debug this part not useful?
//		/* Register the Applet (copied code) */
//		if (bArray[bOffset] == 0)
//			wal.register();
//		else
//			wal.register(bArray, (short) (bOffset + 1), (byte) (bArray[bOffset]));
	}

	public boolean select() {
		/*
		 * Application has been selected: Do session cleanup operation
		 */
		
		// Destroy the IO objects (if they exist)
		if (setupDone) {
			om.destroyObject(IN_OBJECT_CLA, IN_OBJECT_ID, true);
			om.destroyObject(OUT_OBJECT_CLA, OUT_OBJECT_ID, true);
		}
		LogOutAll();
		return true;
	}

	public void deselect() {
		// Destroy the IO objects (if they exist)
		if (setupDone) {
			om.destroyObject(IN_OBJECT_CLA, IN_OBJECT_ID, true);
			om.destroyObject(OUT_OBJECT_CLA, OUT_OBJECT_ID, true);
		}
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
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);

		switch (ins) {
		case INS_SETUP:
			setup(apdu, buffer);
			break;
		case INS_GEN_KEYPAIR:
			GenerateKeyPair(apdu, buffer);
			break;
		case INS_GEN_KEYSYM:
			GenerateSymmetricKey(apdu, buffer);
			break;
		case INS_IMPORT_KEY:
			ImportKey(apdu, buffer);
			break;
		case INS_GET_PUBLIC_FROM_PRIVATE:
			getPublicKeyFromPrivate(apdu, buffer);
			break;
//		case INS_EXPORT_KEY:
//			ExportKey(apdu, buffer);
//			break;
		case INS_COMPUTE_CRYPT:
			ComputeCrypt(apdu, buffer);
			break;
		case INS_COMPUTE_SIGN:
			ComputeSign(apdu, buffer);
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
//		case INS_GET_CHALLENGE:
//			GetChallenge(apdu, buffer);
//			break;
//		case INS_EXT_AUTH:
//			ExternalAuthenticate(apdu, buffer);
//			break;
		case INS_CREATE_OBJ:
			CreateObject(apdu, buffer);
			break;
		case INS_DELETE_OBJ:
			DeleteObject(apdu, buffer);
			break;
		case INS_READ_OBJ:
			ReadObject(apdu, buffer);
			break;
		case INS_WRITE_OBJ:
			WriteObject(apdu, buffer);
			break;
		case INS_SIZE_OBJ:	
			GetObjectSize(apdu, buffer);
			break;
		case INS_LIST_PINS:
			ListPINs(apdu, buffer);
			break;
		case INS_LIST_OBJECTS:
			ListObjects(apdu, buffer);
			break;
		case INS_LIST_KEYS:
			ListKeys(apdu, buffer);
			break;
		case INS_GET_STATUS:
			GetStatus(apdu, buffer);
			break;
		case INS_COMPUTE_SHA512:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED); // only for debug purpose
			//computeSha512(apdu, buffer);
			break;
		case INS_COMPUTE_HMAC:
			//ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED); // only for debug purpose
			computeHmac(apdu, buffer);
			break;
		case INS_BIP32_IMPORT_SEED:
			importBIP32Seed(apdu, buffer);
			break;
		case INS_BIP32_GET_AUTHENTIKEY:
			getBIP32AuthentiKey(apdu, buffer);
			break;
		case INS_BIP32_GET_EXTENDED_KEY:
			getBIP32ExtendedKey(apdu, buffer);
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
		case INS_BIP32_SET_EXTENDED_KEY:	
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED); // only for debug purpose
			//setBIP32ExtendedKey(apdu, buffer);
			break; 
		case INS_PARSE_TRANSACTION:
			ParseTransaction(apdu, buffer);
			break;
//		case INS_TEST_SHA1:	
//			byte p1= buffer[ISO7816.OFFSET_P1];
//			switch(p1){
//				// add_carry
//				case 0x00:
//					Sha512.test_add_carry(buffer, (short)ISO7816.OFFSET_CDATA, buffer, (short)(ISO7816.OFFSET_CDATA+8));
//					break;
//				case 0x01:
//					Sha512.test_add_carry_fast(buffer, (short)ISO7816.OFFSET_CDATA, buffer, (short)(ISO7816.OFFSET_CDATA+8));
//					break;
//				case 0x02:
//					Sha512.test_add_carry_fast2(buffer, (short)ISO7816.OFFSET_CDATA, buffer, (short)(ISO7816.OFFSET_CDATA+8));
//					break;
//				case 0x03:
//					Sha512.test_add_carry_fast3(buffer, (short)ISO7816.OFFSET_CDATA, buffer, (short)(ISO7816.OFFSET_CDATA+8));
//					break;
//				// Ch	
//				case 0x04:					
//					Sha512.test_Ch(buffer, (short)ISO7816.OFFSET_CDATA, buffer, (short)(ISO7816.OFFSET_CDATA+8), buffer, (short)(ISO7816.OFFSET_CDATA+16), buffer, (short)(ISO7816.OFFSET_CDATA+24));
//					break;
//				case 0x05:					
//					Sha512.test_Ch_fast(buffer, (short)ISO7816.OFFSET_CDATA, buffer, (short)(ISO7816.OFFSET_CDATA+8), buffer, (short)(ISO7816.OFFSET_CDATA+16), buffer, (short)(ISO7816.OFFSET_CDATA+24));
//					break;
//				// Maj	
//				case 0x06:					
//					Sha512.test_Maj(buffer, (short)ISO7816.OFFSET_CDATA, buffer, (short)(ISO7816.OFFSET_CDATA+8), buffer, (short)(ISO7816.OFFSET_CDATA+16), buffer, (short)(ISO7816.OFFSET_CDATA+24));
//					break;
//				case 0x07:					
//					Sha512.test_Maj_fast(buffer, (short)ISO7816.OFFSET_CDATA, buffer, (short)(ISO7816.OFFSET_CDATA+8), buffer, (short)(ISO7816.OFFSET_CDATA+16), buffer, (short)(ISO7816.OFFSET_CDATA+24));
//					break;	
//				// E0-E1-Sig0-Sig1	
//				case 0x10:					
//					Sha512.test_E0_opt(buffer, (short)ISO7816.OFFSET_CDATA, buffer, (short)(ISO7816.OFFSET_CDATA+8));
//					break;
//				case 0x11:					
//					Sha512.test_E0_fast(buffer, (short)ISO7816.OFFSET_CDATA, buffer, (short)(ISO7816.OFFSET_CDATA+8));
//					break;	
//				case 0x12:					
//					Sha512.test_E1_opt(buffer, (short)ISO7816.OFFSET_CDATA, buffer, (short)(ISO7816.OFFSET_CDATA+8));
//					break;
//				case 0x13:					
//					Sha512.test_E1_fast(buffer, (short)ISO7816.OFFSET_CDATA, buffer, (short)(ISO7816.OFFSET_CDATA+8));
//					break;	
//				case 0x14:					
//					Sha512.test_Sig0_opt(buffer, (short)ISO7816.OFFSET_CDATA, buffer, (short)(ISO7816.OFFSET_CDATA+8));
//					break;
//				case 0x15:					
//					Sha512.test_Sig0_fast(buffer, (short)ISO7816.OFFSET_CDATA, buffer, (short)(ISO7816.OFFSET_CDATA+8));
//					break;	
//				case 0x16:					
//					Sha512.test_Sig1_opt(buffer, (short)ISO7816.OFFSET_CDATA, buffer, (short)(ISO7816.OFFSET_CDATA+8));
//					break;
//				case 0x17:					
//					Sha512.test_Sig1_fast(buffer, (short)ISO7816.OFFSET_CDATA, buffer, (short)(ISO7816.OFFSET_CDATA+8));
//					break;	
//				case 0x20:					
//					Sha512.test_updateW(buffer, ISO7816.OFFSET_CDATA, buffer[ISO7816.OFFSET_P2]);
//					break;
//				case 0x21:					
//					Sha512.test_updateW_fast(buffer, ISO7816.OFFSET_CDATA, buffer[ISO7816.OFFSET_P2]);
//					break; 
//
//			}
//			apdu.setOutgoingAndSend((short) 0, (short)(128));
//			break;
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
     *        secmemsize(2b) | memsize(2b) | ACL(3b) |
     *        option_flags(2b) | 
     *        hmacksha1_key(20b) | amount_limit(8b)]
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

		pins[0] = new OwnerPIN(pin_tries, PIN_MAX_SIZE);
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
		short mem_size = Util.getShort(buffer, base);
		base += (short) 2;
		bytesLeft-=4;
		
		create_object_ACL = buffer[base++];
		create_key_ACL = buffer[base++];
		create_pin_ACL = buffer[base++];
		bytesLeft-=3;
		
		mem = new MemoryManager((short) mem_size);
		om = new ObjectManager(mem);
		bip32_mem = new MemoryManager((short) secmem_size);
		bip32_om = new ObjectManager(bip32_mem);
		
		keys = new Key[MAX_NUM_KEYS];
		keyACLs = new byte[(short) (MAX_NUM_KEYS * KEY_ACL_SIZE)];
		keyTries = new byte[MAX_NUM_KEYS];
		for (byte i = (byte) 0; i < (byte) MAX_NUM_KEYS; i++)
			keyTries[i] = MAX_KEY_TRIES;
		keyPairs = new KeyPair[MAX_NUM_KEYS];
		ciphers = new Cipher[MAX_NUM_KEYS];
		signatures = new Signature[MAX_NUM_KEYS];
		ciph_dirs = new byte[MAX_NUM_KEYS];
		for (byte i = (byte) 0; i < (byte) MAX_NUM_KEYS; i++)
			ciph_dirs[i] = (byte) 0xFF;

		logged_ids = 0x00; // No identities logged in
		//getChallengeDone = false; // No GetChallenge() issued so far
		
		STD_PUBLIC_ACL = new byte[KEY_ACL_SIZE];
		for (byte i = (byte) 0; i < (byte) KEY_ACL_SIZE; i += (short) 2)
			Util.setShort(STD_PUBLIC_ACL, i, (short) 0x0000);
		
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
		randomData = null; // Will be created on demand when needed
		keyAgreement = KeyAgreement.getInstance(ALG_EC_SVDP_DH_PLAIN, false); 
		sigECDSA= Signature.getInstance(ALG_ECDSA_SHA_256, false); 
		aes128= Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);
		
		// HD wallet
		Sha512.init();
		HmacSha512.init(tmpBuffer);
		EccComputation.init(tmpBuffer);
		// bip32 material
		bip32_seeded= false;
		bip32_master_compbyte=0x04;
		bip32_masterkey= (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_256, false);
		bip32_masterchaincode= (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_256, false);
		bip32_encryptkey= (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
		bip32_masterACL= new byte[KEY_ACL_SIZE];
		bip32_extendedACL= new byte[KEY_ACL_SIZE];
		// object containing the current extended key
		bip32_extendedkey= (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, LENGTH_EC_FP_256, false);
		Secp256k1.setCommonCurveParameters(bip32_extendedkey);
		// key used to authenticate sensitive data from applet
		bip32_authentikey= (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, LENGTH_EC_FP_256, false);
		Secp256k1.setCommonCurveParameters(bip32_authentikey);
		// key used to recover public key from private
		bip32_pubkey= (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, LENGTH_EC_FP_256, false);
		Secp256k1.setCommonCurveParameters(bip32_pubkey);
		
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
			// transaction confirmation based on hmacsha160
			if ((option_flags & HMAC_CHALRESP_2FA)==HMAC_CHALRESP_2FA){
				Util.arrayCopyNonAtomic(buffer, base, transactionData, OFFSET_TRANSACTION_HMACKEY, (short)20); 
				base+=(short)20;
				bytesLeft-=(short)20;
				Util.arrayCopyNonAtomic(buffer, base, transactionData, OFFSET_TRANSACTION_LIMIT, (short)8); 
				base+=(short)8;
				bytesLeft-=(short)8;
			}
		}
		
		setupDone = true;
	}

	/********** UTILITY FUNCTIONS **********/

	/*
	 * SendData() wraps the setOutgoing(), setLength(), .. stuff * that could be
	 * necessary to be fully JavaCard compliant.
	 */
	private void sendData(APDU apdu, byte[] data, short offset, short size) {
		if (size > EXT_APDU_BUFFER_SIZE)
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		apdu.setOutgoing();
		apdu.setOutgoingLength(size);
		apdu.sendBytesLong(data, offset, size);
	}

	/* Retrieves the full contents from the apdu object in case of 
	 * an extended APDU. */
	private void getData(APDU apdu, byte[] src, short bytesRead, byte[] dst) {
		short recvLen = 0;
		short apduOffset = bytesRead;

		Util.arrayCopyNonAtomic(src, (short) 0, dst, (short) 0, apduOffset);
		do {
			recvLen = apdu.receiveBytes((short) 0);
			Util.arrayCopyNonAtomic(src, (short) 0, dst, apduOffset, recvLen);
			apduOffset += recvLen;
		} while (recvLen > 0);
	}

	/*
	 * Retrieves the Cipher object to be used w/ the specified key * and
	 * algorithm id (Cipher.ALG_XX). * If exists, check it has the proper
	 * algorithm and throws * SW_OP_NOT_ALLOWED if not * If not, creates it
	 */
	private Cipher getCipher(byte key_nb, byte alg_id) {
		if (ciphers[key_nb] == null) {
			ciphers[key_nb] = Cipher.getInstance(alg_id, false);
		} else if (ciphers[key_nb].getAlgorithm() != alg_id)
			ISOException.throwIt(SW_OPERATION_NOT_ALLOWED);
		return ciphers[key_nb];
	}

	/*
	 * Retrieves the Signature object to be used w/ the specified key * and
	 * algorithm id (Signature.ALG_XX). * If exists, check it has the proper
	 * algorithm and throws * SW_OPERATION_NOT_ALLOWED if not * If does not
	 * exist, creates it
	 */
	private Signature getSignature(byte key_nb, byte alg_id) {
		if (signatures[key_nb] == null) {
			try {
				signatures[key_nb] = Signature.getInstance(alg_id, false);
			} catch (Exception e) {
				ISOException.throwIt(((CardRuntimeException) e).getReason());
			}
		} else if (signatures[key_nb].getAlgorithm() != alg_id)
			ISOException.throwIt(SW_OPERATION_NOT_ALLOWED);
		return signatures[key_nb];
	}

	/**
	 * Retrieves the Key object to be used w/ the specified key number, key type
	 * (KEY_XX) and size. If exists, check it has the proper key type If not,
	 * creates it.
	 * 
	 * @return Retrieved Key object or throws SW_UNATUTHORIZED,
	 *         SW_OPERATION_NOT_ALLOWED
	 */
	private Key getKey(byte key_nb, byte key_type, short key_size) {
		
		if (keys[key_nb] == null) {
			// We have to create the Key

			/* Check that Identity n.0 is logged */
			if ((create_key_ACL == (byte) 0xFF)
					|| (((logged_ids & create_key_ACL) == (short) 0x0000) && (create_key_ACL != (byte) 0x00)))
				ISOException.throwIt(SW_UNAUTHORIZED);
			
			keys[key_nb] = KeyBuilder.buildKey(key_type, key_size, false);
			
		} else {
			// Key already exists: check size & type
			/*
			 * TODO: As an option, we could just discard and recreate if not of
			 * the correct type, but creates trash objects
			 */
			if ((keys[key_nb].getSize() != key_size) || (keys[key_nb].getType() != key_type))
				ISOException.throwIt(SW_OPERATION_NOT_ALLOWED);
		}
		return keys[key_nb];
	}

	/** Check from key_nb key ACL if an operation can be done */
	boolean authorizeKeyOp(byte key_nb, byte op) {
		short acl_offset = (short) (key_nb * KEY_ACL_SIZE+ op);
		short required_ids = Util.getShort(keyACLs, acl_offset);
		return ((required_ids != (short) 0xFFFF) && ((short) (required_ids & logged_ids) == required_ids));
	}
	
	/** Check from ACL if the corresponding key can be overwritten */
	boolean authorizeKeyOp(byte[] ACL, byte op) {
		short required_ids = Util.getShort(ACL, (short)op);
		return ((required_ids != (short) 0xFFFF) && ((short) (required_ids & logged_ids) == required_ids));
	}
			
	/** Returns an ACL that requires current logged in identities. */
	byte[] getCurrentACL() {
		if (acl == null)
			acl = new byte[KEY_ACL_SIZE]; //to do: avoid allocation outside setup?
		byte i;
		for (i = (byte) 0; i < KEY_ACL_SIZE; i += (byte) 2)
			Util.setShort(acl, i, logged_ids);
		return acl;
	}

//	/** Returns an ACL that disables all operations for the application. */
//	byte[] getRestrictedACL() {
//		if (acl == null)
//			acl = new byte[KEY_ACL_SIZE]; //to do: avoid allocation outside setup?
//		byte i;
//		for (i = (byte) 0; i < KEY_ACL_SIZE; i += (byte) 2)
//			Util.setShort(acl, i, (short) 0xFFFF);
//		return acl;
//	}

//	/** Registers login of strong identity associated with a key number */
//	private void LoginStrongIdentity(byte key_nb) {
//		logged_ids |= (short) (((short) 0x01) << (key_nb + 8));
//	}

	/**
	 * Registers logout of an identity. This must be called anycase when a PIN
	 * verification or external authentication fail
	 */
	private void LogoutIdentity(byte id_nb) {
		logged_ids &= (short) ~(0x0001 << id_nb);
	}

	/** Deletes and zeros the IO objects and throws the passed in exception */
	private void ThrowDeleteObjects(short exception) {
		om.destroyObject(IN_OBJECT_CLA, IN_OBJECT_ID, true);
		om.destroyObject(OUT_OBJECT_CLA, OUT_OBJECT_ID, true);
		ISOException.throwIt(exception);
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
	 * This function performs encryption/decryption on provided data, using a key on
	 * the card. It also allows proper initialization of the card cipher with custom data, if
	 * required by the application. Usually, this function is called 1 time for cipher
	 * initialization (CIPHER_INIT), 0 or more times for intermediate data processing
	 * (CIPHER_UPDATE) and 1 time for last data processing (CIPHER_FINAL). 
	 * 
	 * ins: 0x36
	 * p1: key number (0x00-0x0F)
	 * p2: operation (Init-Update-Final)
	 * data(Init): [cipher_mode(1b)|cipher_direction(1b)|cipher_location(1b)|option_data_size(1b)|option_data]
	 * data(Update/Final): [data_location(1b)|data_size(2b)|data]
	 * 
	 * return(init): [IV(blocksize)] or none (ECB mode or RSA)
	 * return(Update/Final): [data_size(2b)|processed_data]
	 */
	private void ComputeCrypt(APDU apdu, byte[] apduBuffer) {
		
		/* Buffer pointer */
		byte[] buffer = apduBuffer;
		
		//extended length
		short bytesLeft = apdu.setIncomingAndReceive();
		short LC = apdu.getIncomingLength();
		short dataOffset = apdu.getOffsetCdata();
		
		if ((short) (LC + dataOffset) > EXT_APDU_BUFFER_SIZE)
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);		
		/* Is this an extended APDU? */
		if (bytesLeft != LC) {
			getData(apdu, apduBuffer, (short) (dataOffset + bytesLeft), recvBuffer);
			buffer = recvBuffer;
			bytesLeft = LC;
		}
		
		byte key_nb = buffer[ISO7816.OFFSET_P1];
		if ((key_nb < 0) || (key_nb >= MAX_NUM_KEYS) || (keys[key_nb] == null))
			ISOException.throwIt(SW_INCORRECT_P1);
		/* Enforce Access Control */
		if (!authorizeKeyOp(key_nb,ACL_USE))
			ISOException.throwIt(SW_UNAUTHORIZED);
		byte op = buffer[ISO7816.OFFSET_P2];
		Key key = keys[key_nb];
		byte ciph_mode;
		byte ciph_dir;
		byte ciph_alg_id=0;
		byte data_location;
		short size;
		Cipher ciph;
		
		switch (op) {
		case OP_INIT:
			if (bytesLeft < 3)
				ISOException.throwIt(SW_INVALID_PARAMETER);
			ciph_mode = buffer[dataOffset];
			ciph_dir = buffer[(short) (dataOffset + 1)];
			if (ciph_dir!=Cipher.MODE_ENCRYPT &&  ciph_dir!=Cipher.MODE_DECRYPT )
				ISOException.throwIt(SW_INVALID_PARAMETER);
			data_location = buffer[(short) (dataOffset + 2)];
			if (data_location!=DL_APDU) // only support data in apdu
				ISOException.throwIt(SW_INVALID_PARAMETER);
			dataOffset+= 3;
			bytesLeft-= 3;
			
			if (bytesLeft < 2)
				ISOException.throwIt(SW_INVALID_PARAMETER);
			size = Util.getShort(buffer, dataOffset);
			if (bytesLeft < (short) (2 + size))
				ISOException.throwIt(SW_INVALID_PARAMETER);
			
			short IVlength=0;
			switch (key.getType()) {
				case KeyBuilder.TYPE_RSA_PUBLIC:
				case KeyBuilder.TYPE_RSA_PRIVATE:
				case KeyBuilder.TYPE_RSA_CRT_PRIVATE:
					if (ciph_mode == Cipher.ALG_RSA_NOPAD)
						ciph_alg_id = Cipher.ALG_RSA_NOPAD;
					else if (ciph_mode == Cipher.ALG_RSA_PKCS1)
						ciph_alg_id = Cipher.ALG_RSA_PKCS1;
					else
						ISOException.throwIt(SW_INVALID_PARAMETER);
					break;
				case KeyBuilder.TYPE_DES:
					if (ciph_mode == Cipher.ALG_DES_CBC_NOPAD){
						IVlength= (short)(8);
						ciph_alg_id = Cipher.ALG_DES_CBC_NOPAD;
					}
					else if (ciph_mode == Cipher.ALG_DES_ECB_NOPAD)
						ciph_alg_id = Cipher.ALG_DES_ECB_NOPAD;
					else
						ISOException.throwIt(SW_INVALID_PARAMETER);
					break;
				case KeyBuilder.TYPE_AES:
					if (ciph_mode == Cipher.ALG_AES_BLOCK_128_CBC_NOPAD){
						IVlength= (short)(16);
						ciph_alg_id = Cipher.ALG_AES_BLOCK_128_CBC_NOPAD;
					}
					else if (ciph_mode == Cipher.ALG_AES_BLOCK_128_ECB_NOPAD)
						ciph_alg_id = Cipher.ALG_AES_BLOCK_128_ECB_NOPAD;
					else
						ISOException.throwIt(SW_INVALID_PARAMETER);
					break;
				default:
					ISOException.throwIt(SW_INTERNAL_ERROR);
					return; // Compiler warning (ciph_alg_id unset)
			}
			// init cipher
			// encrypt
			// 		IV=0 (rsa, ecb)
			//		IV!=0 generateOnCard (des/aes cbc)
			// decrypt
			// 		IV=0 (rsa, ecb)
			// 		IV!=0 getFromBuffer (des/aes cbc)
			ciph = getCipher(key_nb, ciph_alg_id);
			if (IVlength == (short) 0)
				ciph.init(key, (ciph_dir == Cipher.MODE_ENCRYPT) ? Cipher.MODE_ENCRYPT : Cipher.MODE_DECRYPT);
			else if (ciph_dir== Cipher.MODE_ENCRYPT){
				if (randomData == null)
					randomData = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
				randomData.generateData(buffer,(short)0,IVlength);
				ciph.init(key, Cipher.MODE_ENCRYPT, buffer,	(short)0, IVlength);
				apdu.setOutgoingAndSend((short) 0, IVlength);
			}
			else if (ciph_dir== Cipher.MODE_DECRYPT){
				ciph.init(key, Cipher.MODE_DECRYPT, buffer,	(short) (dataOffset + 2), IVlength);
				// ciph.init(key, (ciph_dir == Cipher.MODE_ENCRYPT) ? Cipher.MODE_ENCRYPT : Cipher.MODE_DECRYPT, buffer,	(short) (dataOffset + 2), size);
			}
			ciph_dirs[key_nb] = ciph_dir;
			break;

		case OP_PROCESS:
		case OP_FINALIZE:
		
			ciph_dir = ciph_dirs[key_nb];
			if (ciph_dir!=Cipher.MODE_ENCRYPT && ciph_dir!=Cipher.MODE_DECRYPT)
				// Internal error because it should have been checked on INIT
				ISOException.throwIt(SW_INTERNAL_ERROR);

			ciph = ciphers[key_nb];
			if (ciph == null)
				/* Don't know what is incorrect: just say incorrect
				 * parameters we guess it was specified a wrong key number */
				ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
			
			data_location = buffer[dataOffset];
			if(data_location!=DL_APDU)
				ISOException.throwIt(SW_INVALID_PARAMETER);
			dataOffset+=1;
			bytesLeft-=1;

			if (bytesLeft < 2)
				ISOException.throwIt(SW_INVALID_PARAMETER);
			size = Util.getShort(buffer, dataOffset);
			if (bytesLeft < (short) (2 + size))
				ISOException.throwIt(SW_INVALID_PARAMETER);
			
			short sizeout=0;
			if (op == OP_PROCESS)
				sizeout=ciph.update(buffer, (short) (dataOffset + 2), size, buffer, (short) 2);
			else /* op == OP_FINAL */
				sizeout=ciph.doFinal(buffer, (short) (dataOffset + 2), size, buffer, (short) 2);
			
			// Also copies the Short size information
			Util.setShort(buffer,(short)0,  sizeout);
			sendData(apdu, buffer, (short) 0, (short) (sizeout + 2));
			break;

		default:
			ISOException.throwIt(SW_INCORRECT_P2);
		} // switch(op) 
	}

	/** 
	 * This function performs signature/verification on provided data, using a key on
	 * the card. It also allows proper initialization of the card cipher with custom data, if
	 * required by the application. Usually, this function is called 1 time for cipher
	 * initialization (CIPHER_INIT), 0 or more times for intermediate data processing
	 * (CIPHER_UPDATE) and 1 time for last data processing (CIPHER_FINAL). 
	 * 
	 * ins: 0x37
	 * p1: key number (0x00-0x0F)
	 * p2: operation (Init-Update-Final)
	 * data(Init): [cipher_mode(1b)|cipher_direction(1b)|cipher_location(1b)|option_data_size(1b)|option_data]
	 * data(Update/Final): [data_location(1b)|data_size(2b)|data]
	 * 
	 * return(init/update): none
	 * return(final-signature): signature in ASN1 format
	 * return(final-verification): none (throws exception in case of signature)
	 */
	private void ComputeSign(APDU apdu, byte[] apduBuffer) {
		
		/* Buffer pointer */
		byte[] buffer = apduBuffer;
		
		//extended length
		short bytesLeft = apdu.setIncomingAndReceive();
		short LC = apdu.getIncomingLength();
		short dataOffset = apdu.getOffsetCdata();
		
		if ((short) (LC + dataOffset) > EXT_APDU_BUFFER_SIZE)
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);		
		/* Is this an extended APDU? */
		if (bytesLeft != LC) {
			getData(apdu, apduBuffer, (short) (dataOffset + bytesLeft), recvBuffer);
			buffer = recvBuffer;
			bytesLeft = LC;
		}
		
		byte key_nb = buffer[ISO7816.OFFSET_P1];
		if ((key_nb < 0) || (key_nb >= MAX_NUM_KEYS) || (keys[key_nb] == null))
			ISOException.throwIt(SW_INCORRECT_P1);
		/* Enforce Access Control */
		if (!authorizeKeyOp(key_nb,ACL_USE))
			ISOException.throwIt(SW_UNAUTHORIZED);
		byte op = buffer[ISO7816.OFFSET_P2];
		Key key = keys[key_nb];
		byte ciph_mode; 
		byte ciph_dir;
		byte ciph_alg_id=0;
		byte data_location;
		short size;
		Signature sign;
		
		switch (op) {
		case OP_INIT:
			if (bytesLeft < 3)
				ISOException.throwIt(SW_INVALID_PARAMETER);
			ciph_mode = buffer[dataOffset];
			ciph_dir = buffer[(short) (dataOffset + 1)];
			if (ciph_dir!=Signature.MODE_SIGN && ciph_dir!=Signature.MODE_VERIFY )
				ISOException.throwIt(SW_INVALID_PARAMETER);
			
			data_location = buffer[(short) (dataOffset + 2)];
			if (data_location!=DL_APDU)
				ISOException.throwIt(SW_INVALID_PARAMETER);
			dataOffset+=3;
			bytesLeft-=3;
		
			if (bytesLeft < 2)
				ISOException.throwIt(SW_INVALID_PARAMETER);
			size = Util.getShort(buffer, dataOffset);
			if (bytesLeft < (short) (2 + size))
				ISOException.throwIt(SW_INVALID_PARAMETER);
				
			switch (key.getType()) {
				case KeyBuilder.TYPE_RSA_PUBLIC:
				case KeyBuilder.TYPE_RSA_PRIVATE:
				case KeyBuilder.TYPE_RSA_CRT_PRIVATE: // FIXED
					if (ciph_mode==Signature.ALG_RSA_MD5_PKCS1) // FIXED
						ciph_alg_id = Signature.ALG_RSA_MD5_PKCS1; // ALG_RSA_SHA_PKCS1 instead of ALG_RSA_MD5_PKCS1?
					else // FIXED
						ISOException.throwIt(SW_UNSUPPORTED_FEATURE);
					break;
// For elliptic curves, use signTransaction and signMessage instead					
//				case KeyBuilder.TYPE_EC_FP_PUBLIC:
//				case KeyBuilder.TYPE_EC_FP_PRIVATE:
//					if (ciph_mode == ALG_ECDSA_SHA_256)
//						ciph_alg_id = ALG_ECDSA_SHA_256; //Signature.ALG_ECDSA_SHA_256; //=33
//					else if (ciph_mode == Signature.ALG_ECDSA_SHA)
//						ciph_alg_id = Signature.ALG_ECDSA_SHA ;
//					else 
//						ISOException.throwIt(SW_INVALID_PARAMETER);
//					break;
				default:
					ISOException.throwIt(SW_INCORRECT_ALG);
					return;
			}
			sign = getSignature(key_nb, ciph_alg_id);
			if (size == (short) 0)
				sign.init(key, (ciph_dir == Signature.MODE_SIGN) ? Signature.MODE_SIGN : Signature.MODE_VERIFY);
			else 
				sign.init(key, (ciph_dir == Signature.MODE_SIGN) ? Signature.MODE_SIGN : Signature.MODE_VERIFY, buffer, (short) (dataOffset + 2), size);
			ciph_dirs[key_nb] = ciph_dir;
			break; // OP_INIT
			
		case OP_PROCESS:
		case OP_FINALIZE:
			ciph_dir = ciph_dirs[key_nb];
			if (ciph_dir!=Signature.MODE_SIGN && ciph_dir!=Signature.MODE_VERIFY )
				// Internal error because it should have been checked on INIT
				ISOException.throwIt(SW_INTERNAL_ERROR);
				
			sign = signatures[key_nb];
			if (sign == null)
				/* Don't know what is incorrect: just say incorrect
				 * parameters we guess it was specified a wrong key number */
				ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
			
			data_location = buffer[dataOffset];
			if (data_location!=DL_APDU)
				ISOException.throwIt(SW_INVALID_PARAMETER);
			dataOffset+=1;
			bytesLeft-=1;
		
			if (bytesLeft < 2){
				ISOException.throwIt(SW_INVALID_PARAMETER);}
			size = Util.getShort(buffer, dataOffset);
			if (bytesLeft < (short) (2 + size)){
				ISOException.throwIt(SW_INVALID_PARAMETER);}
			
			if (op == OP_PROCESS){
				sign.update(buffer, (short) (dataOffset + 2), size);
			}else { // OP_FINALIZE
				if (ciph_dir == Signature.MODE_SIGN) {
					short sign_size = sign.sign(buffer, (short) (dataOffset + 2), size, buffer, (short) 0);
					if (sign_size > sign.getLength())
						// We got a buffer overflow (unless we were in memory end and got an exception...)
						ISOException.throwIt(SW_INTERNAL_ERROR);
						//ISOException.throwIt(Util.makeShort((byte)(sign_size&0xFF), (byte)(sign.getLength())));
					sendData(apdu, buffer, (short)0, sign_size);
				} else { // ciph_dir == CD_VERIFY
					if (bytesLeft < (short) (2 + size + 2))
						ISOException.throwIt(SW_INVALID_PARAMETER);
					short sign_size = Util.getShort(buffer, (short) (dataOffset + 2 + size));
					if (bytesLeft < (short) (2 + size + 2 + sign_size))
						ISOException.throwIt(SW_INVALID_PARAMETER);
					//if (sign_size != sign.getLength()) //commented for debug: size mismatch for ECDSA sig: sign.getLength()==0x38, sign_size=0x36
						//ISOException.throwIt(SW_INVALID_PARAMETER);
					if (!sign.verify(buffer, (short) (dataOffset + 2), size, buffer, (short) (dataOffset + 2 + size + 2), sign_size))
						ISOException.throwIt(SW_SIGNATURE_INVALID);
				}
			}
			break;
			
		default:
			ISOException.throwIt(SW_INCORRECT_P2);
		} // switch(op)
	}
	
	/** 
	 * This function generates a key pair using the card's on board key generation
	 * process. The key number (or numbers if a key pair is being generated), algorithm
	 * type, and algorithm parameters are specified by arguments P1 and P2 and by
	 * provided DATA.
	 * 
	 * ins: 0x30
	 * p1: private key number (0x00-0x0F)
	 * p2: public key number (0x00-0x0F)
	 * data: [Key Generation Parameters] 
	 * return: none
	 */
	private void GenerateKeyPair(APDU apdu, byte[] buffer) {
		short bytesLeft = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
		if (bytesLeft != apdu.setIncomingAndReceive())
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		byte alg_id = buffer[OFFSET_GENKEY_ALG];
		switch (alg_id) {
			case KeyPair.ALG_RSA:
			case KeyPair.ALG_RSA_CRT:
				GenerateKeyPairRSA(buffer);
				break;
			case KeyPair.ALG_EC_FP:
				//GenerateKeyPairECFP(buffer);
				GeneratePrivateKeyECFP(buffer);
				break;
			default:
				ISOException.throwIt(SW_INCORRECT_ALG);
		}
	}
	
	// Data has already been received 
	private void GenerateKeyPairRSA(byte[] buffer) {
		byte prv_key_nb = buffer[ISO7816.OFFSET_P1];
		if ((prv_key_nb < 0) || (prv_key_nb >= MAX_NUM_KEYS))
			ISOException.throwIt(SW_INCORRECT_P1);
		byte pub_key_nb = buffer[ISO7816.OFFSET_P2];
		if ((pub_key_nb < 0) || (pub_key_nb >= MAX_NUM_KEYS))
			ISOException.throwIt(SW_INCORRECT_P2);
		if (pub_key_nb == prv_key_nb)
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
		byte alg_id = buffer[OFFSET_GENKEY_ALG];
		short key_size = Util.getShort(buffer, OFFSET_GENKEY_SIZE);
		byte options = buffer[OFFSET_GENKEY_OPTIONS];
		RSAPublicKey pub_key = (RSAPublicKey) getKey(pub_key_nb, KeyBuilder.TYPE_RSA_PUBLIC, key_size);
		RSAPrivateKey prv_key = (RSAPrivateKey) getKey(prv_key_nb, alg_id == KeyPair.ALG_RSA ? KeyBuilder.TYPE_RSA_PRIVATE : KeyBuilder.TYPE_RSA_CRT_PRIVATE,	key_size);
		/* If we're going to overwrite a keyPair's contents, check ACL */
		if (pub_key.isInitialized() && !authorizeKeyOp(pub_key_nb,ACL_WRITE))
			ISOException.throwIt(SW_UNAUTHORIZED);
		if (prv_key.isInitialized() && !authorizeKeyOp(prv_key_nb,ACL_WRITE))
			ISOException.throwIt(SW_UNAUTHORIZED);
		/* Store private key ACL */
		Util.arrayCopy(buffer, OFFSET_GENKEY_PRV_ACL, keyACLs, (short) (prv_key_nb * KEY_ACL_SIZE), KEY_ACL_SIZE);
		/* Store public key ACL */
		Util.arrayCopy(buffer, OFFSET_GENKEY_PUB_ACL, keyACLs, (short) (pub_key_nb * KEY_ACL_SIZE), KEY_ACL_SIZE);
		switch (options) {
		case OPT_DEFAULT:
			/* As the default was specified, if public key already * exist we
			 * have to invalidate it, otherwise its parameters * would be used
			 * in place of the default ones */
			if (pub_key.isInitialized())
				pub_key.clearKey();
			break;
		case OPT_RSA_PUB_EXP:
			short exp_length = Util.getShort(buffer, OFFSET_GENKEY_RSA_PUB_EXP_LENGTH);
			pub_key.setExponent(buffer, OFFSET_GENKEY_RSA_PUB_EXP_VALUE, exp_length);
			break;
		default:
			ISOException.throwIt(SW_INVALID_PARAMETER);
		}
		/* TODO: Migrate checks on KeyPair on the top, so we avoid resource
		 * allocation on error conditions  */
		/* If no keypair was previously used, ok. If different keypairs were
		 * used, or for 1 key there is a keypair but the other key not, then
		 * error If the same keypair object was used previously, check keypair
		 * size & type   */
		if ((keyPairs[pub_key_nb] == null) && (keyPairs[prv_key_nb] == null)) {
			keyPairs[pub_key_nb] = new KeyPair(pub_key, prv_key);
			keyPairs[prv_key_nb] = keyPairs[pub_key_nb];
		} else if (keyPairs[pub_key_nb] != keyPairs[prv_key_nb])
			ISOException.throwIt(SW_OPERATION_NOT_ALLOWED);
		KeyPair kp = keyPairs[pub_key_nb];
		if ((kp.getPublic() != pub_key) || (kp.getPrivate() != prv_key))
			// This should never happen according with this Applet policies
			ISOException.throwIt(SW_INTERNAL_ERROR);
		// We Rely on genKeyPair() to make all necessary checks about types
		kp.genKeyPair();
	}
	
//	// Bitcoin
//	// not supported by current chips?
//	// Data has already been received
//	private void GenerateKeyPairECFP(byte[] buffer){
//		byte prv_key_nb = buffer[ISO7816.OFFSET_P1];
//		if ((prv_key_nb < 0) || (prv_key_nb >= MAX_NUM_KEYS))
//			ISOException.throwIt(SW_INCORRECT_P1);
//		byte pub_key_nb = buffer[ISO7816.OFFSET_P2];
//		if ((pub_key_nb < 0) || (pub_key_nb >= MAX_NUM_KEYS))
//			ISOException.throwIt(SW_INCORRECT_P2);
//		if (pub_key_nb == prv_key_nb)
//			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
//		short key_size = Util.getShort(buffer, OFFSET_GENKEY_SIZE);
//		byte options = buffer[OFFSET_GENKEY_OPTIONS];
//		ECPublicKey pub_key = (ECPublicKey) getKey(pub_key_nb, KeyBuilder.TYPE_EC_FP_PUBLIC, key_size);
//		ECPrivateKey prv_key = (ECPrivateKey) getKey(prv_key_nb, KeyBuilder.TYPE_EC_FP_PRIVATE, key_size);
//		/* If we're going to overwrite a keyPair's contents, check ACL */
//		if (pub_key.isInitialized() && !authorizeKeyOp(pub_key_nb,ACL_WRITE))
//			ISOException.throwIt(SW_UNAUTHORIZED);
//		if (prv_key.isInitialized() && !authorizeKeyOp(prv_key_nb,ACL_WRITE))
//			ISOException.throwIt(SW_UNAUTHORIZED);
//		/* Store private key ACL */
//		Util.arrayCopy(buffer, OFFSET_GENKEY_PRV_ACL, keyACLs, (short) (prv_key_nb * KEY_ACL_SIZE), KEY_ACL_SIZE);
//		/* Store public key ACL */
//		Util.arrayCopy(buffer, OFFSET_GENKEY_PUB_ACL, keyACLs, (short) (pub_key_nb * KEY_ACL_SIZE), KEY_ACL_SIZE);
//		switch (options) {
//        	case OPT_DEFAULT:
//	            // As default params were specified, we have to clear the public key
//        		// if already initialized, otherwise their params would be used.
//				if (pub_key.isInitialized())
//					pub_key.clearKey();
//				if (prv_key.isInitialized())
//					prv_key.clearKey();
//                break;
//        	case OPT_EC_SECP256k1:
//        		// Bitcoin uses 256-bit keysize!
//        		if (key_size!=256)
//        			ISOException.throwIt(SW_INVALID_PARAMETER);
//	            // As default params were specified, we have to clear the public key
//        		// if already initialized, otherwise their params would be used.
//				if (pub_key.isInitialized())
//					pub_key.clearKey();
//				if (prv_key.isInitialized())
//					prv_key.clearKey();
//				// PINCOIN default is secp256k1 (over Fp)
//				pub_key.setFieldFP( SECP256K1_P, (short)0, (short)SECP256K1_P.length);
//				prv_key.setFieldFP( SECP256K1_P, (short)0, (short)SECP256K1_P.length);
//				pub_key.setA( SECP256K1_a, (short)0, (short)SECP256K1_a.length);
//				prv_key.setA( SECP256K1_a, (short)0, (short)SECP256K1_a.length);
//				pub_key.setB( SECP256K1_b, (short)0, (short)SECP256K1_b.length);
//				prv_key.setB( SECP256K1_b, (short)0, (short)SECP256K1_b.length);
//				pub_key.setG( SECP256K1_G, (short)0, (short)SECP256K1_G.length);
//				prv_key.setG( SECP256K1_G, (short)0, (short)SECP256K1_G.length);
//				pub_key.setR( SECP256K1_R, (short)0, (short)SECP256K1_R.length);
//				prv_key.setR( SECP256K1_R, (short)0, (short)SECP256K1_R.length);
//				pub_key.setK( SECP256K1_K);
//				prv_key.setK( SECP256K1_K);
//				break;
//            default:
//            	ISOException.throwIt(SW_INVALID_PARAMETER);
//		}
//		/* TODO: Migrate checks on KeyPair on the top, so we avoid resource
//		 * allocation on error conditions		 */
//		/* If no keypair was previously used, ok. If different keypairs were
//		 * used, or for 1 key there is a keypair but the other key not, then
//		 * error If the same keypair object was used previously, check keypair
//		 * size & type							*/
//		if ((keyPairs[pub_key_nb] == null) && (keyPairs[prv_key_nb] == null)) {
//			keyPairs[pub_key_nb] = new KeyPair(pub_key, prv_key);
//			keyPairs[prv_key_nb] = keyPairs[pub_key_nb];
//		} else if (keyPairs[pub_key_nb] != keyPairs[prv_key_nb])
//			ISOException.throwIt(SW_OPERATION_NOT_ALLOWED);
//		KeyPair kp = keyPairs[pub_key_nb];
//		if ((kp.getPublic() != pub_key) || (kp.getPrivate() != prv_key))
//			// This should never happen with this Applet policies
//			ISOException.throwIt(SW_INTERNAL_ERROR);
//		// We Rely on genKeyPair() to make all necessary checks about types
//		try {
//			kp.genKeyPair();
//		} catch (Exception e) {
//			ISOException.throwIt(SW_UNSPECIFIED_ERROR);
//		}		
//	}	

	// Bitcoin
	// Generate only a random private key
	// the corresponding public key can be recovered externally using getPublicKeyFromPrivate()
	private void GeneratePrivateKeyECFP(byte[] buffer){
		byte prv_key_nb = buffer[ISO7816.OFFSET_P1];
		if ((prv_key_nb < 0) || (prv_key_nb >= MAX_NUM_KEYS))
			ISOException.throwIt(SW_INCORRECT_P1);
		short key_size = Util.getShort(buffer, OFFSET_GENKEY_SIZE);
		byte options = buffer[OFFSET_GENKEY_OPTIONS];
		ECPrivateKey prv_key = (ECPrivateKey) getKey(prv_key_nb, KeyBuilder.TYPE_EC_FP_PRIVATE, key_size);
		/* If we're going to overwrite a keyPair's contents, check ACL */
		if (prv_key.isInitialized() && !authorizeKeyOp(prv_key_nb,ACL_WRITE))
			ISOException.throwIt(SW_UNAUTHORIZED);
		/* Store private key ACL */
		Util.arrayCopy(buffer, OFFSET_GENKEY_PRV_ACL, keyACLs, (short) (prv_key_nb * KEY_ACL_SIZE), KEY_ACL_SIZE);
		
		if (randomData == null)
			randomData = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
		
		switch (options) {
        	case OPT_DEFAULT:
	            // As default params were specified, we have to clear the public key
        		// if already initialized, otherwise their params would be used.
				if (prv_key.isInitialized())
					prv_key.clearKey();
                break;
        	case OPT_EC_SECP256k1:
        		// Bitcoin uses 256-bit keysize!
        		if (key_size!=256)
        			ISOException.throwIt(SW_INVALID_PARAMETER);
	            // Satochip default is secp256k1 (over Fp)
        		Secp256k1.setCommonCurveParameters(prv_key);
//				prv_key.setFieldFP( SECP256K1_P, (short)0, (short)SECP256K1_P.length);
//				prv_key.setA( SECP256K1_a, (short)0, (short)SECP256K1_a.length);
//				prv_key.setB( SECP256K1_b, (short)0, (short)SECP256K1_b.length);
//				prv_key.setG( SECP256K1_G, (short)0, (short)SECP256K1_G.length);
//				prv_key.setR( SECP256K1_R, (short)0, (short)SECP256K1_R.length);
//				prv_key.setK( SECP256K1_K);
				// Set secret value from random 
				randomData.generateData(recvBuffer,(short)0,(short)(key_size/8));
				prv_key.setS(recvBuffer, (short)0, (short)(key_size/8));
				Util.arrayFillNonAtomic(recvBuffer, (short)0, (short)(key_size/8), (byte)0);
				break;
            default:
            	ISOException.throwIt(SW_INVALID_PARAMETER);
		}
	}	
	
	/** 
	 * This function generates a symmetric key using the card's on board key generation
	 * process. The key number, key type, and key size (in bits) are specified 
	 * by arguments P1 and P2 and by provided DATA.
	 * 
	 * ins: 0x31
	 * p1: symmetric key number (0x00-0x0F)
	 * p2: 0x00
	 * data: [key_type(1) | key_size(2) | key_ACL(6)] 
	 * return: none
	 */
	private void GenerateSymmetricKey(APDU apdu, byte[] buffer) {
		short bytesLeft = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
		if (bytesLeft != apdu.setIncomingAndReceive())
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		
		byte key_nb = buffer[ISO7816.OFFSET_P1];
		if ((key_nb < 0) || (key_nb >= MAX_NUM_KEYS))
			ISOException.throwIt(SW_INCORRECT_P1);
		/* If we're going to overwrite a key contents, check ACL */
		if ((keys[key_nb] != null) && keys[key_nb].isInitialized() && !authorizeKeyOp(key_nb,ACL_WRITE))
			ISOException.throwIt(SW_UNAUTHORIZED);
		
		/*** Start reading key blob header***/
		// blob header= [ key_type(1) | key_size(2) | key_ACL(6)]
		// Check entire blob header
		if (bytesLeft < 9)
			ISOException.throwIt(SW_INVALID_PARAMETER);
		
		short dataOffset= ISO7816.OFFSET_CDATA;
		byte key_type = buffer[dataOffset];
		dataOffset++; // Skip Key Type
		bytesLeft--;
		short key_size = Util.getShort(buffer, dataOffset);
		dataOffset += (short) 2; // Skip Key Size
		bytesLeft -= (short) 2;
		Util.arrayCopy(buffer, dataOffset, keyACLs, (short) (key_nb * KEY_ACL_SIZE), KEY_ACL_SIZE);
		dataOffset += (short) 6; // Skip ACL
		bytesLeft -= (short) 6;
		
		if (randomData == null)
			randomData = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
		
		switch (key_type) {		
			case KeyBuilder.TYPE_AES:
				AESKey aes_key = (AESKey) getKey(key_nb, key_type, key_size);
				randomData.generateData(recvBuffer,(short)0,(short)(key_size/8));
				aes_key.setKey(recvBuffer, (short)0);
				break;
			case KeyBuilder.TYPE_DES:
				DESKey des_key = (DESKey) getKey(key_nb, key_type, key_size);
				randomData.generateData(recvBuffer,(short)0,(short)(key_size/8));
				des_key.setKey(recvBuffer, (short)0);
				break;
			default:
				ISOException.throwIt(SW_INCORRECT_ALG);		
		}
		// clear recvBuffer
		Util.arrayFillNonAtomic(recvBuffer, (short)0, (short)(key_size/8), (byte)0);
	}
	
	/** 
	 * This function allows the import of a key into the card.
	 * The exact key blob contents depend on the key’s algorithm, type and actual
	 * import parameters. The key's number, algorithm type, and parameters are
	 * specified by arguments P1, P2 and DATA.
	 * 
	 * ins: 0x32
	 * p1: private key number (0x00-0x0F)
	 * p2: 0x00
	 * data: [key_encoding(1) | key_type(1) | key_size(2) | key_ACL(6) | key_blob] 
	 * return: none
	 */
	private void ImportKey(APDU apdu, byte[] apduBuffer) {
		if (apduBuffer[ISO7816.OFFSET_P2] != (byte) 0x00)
			ISOException.throwIt(SW_INCORRECT_P2);
		
		/* Buffer pointer */
		byte[] buffer = apduBuffer;
		
		//extended length
		short bytesLeft = apdu.setIncomingAndReceive();
		short LC = apdu.getIncomingLength();
		short dataOffset = apdu.getOffsetCdata();
		
		if ((short) (LC + dataOffset) > EXT_APDU_BUFFER_SIZE)
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);		
		/* Is this an extended APDU? */
		if (bytesLeft != LC) {
			getData(apdu, apduBuffer, (short) (dataOffset + bytesLeft), recvBuffer);
			buffer = recvBuffer;
			bytesLeft = LC;
		}
		
		byte key_nb = buffer[ISO7816.OFFSET_P1];
		if ((key_nb < 0) || (key_nb >= MAX_NUM_KEYS))
			ISOException.throwIt(SW_INCORRECT_P1);
		/* If we're going to overwrite a key contents, check ACL */
		if ((keys[key_nb] != null) && keys[key_nb].isInitialized() && !authorizeKeyOp(key_nb,ACL_WRITE))
			ISOException.throwIt(SW_UNAUTHORIZED);
		
		/*** Start reading key blob header***/
		// blob header= [ key_encoding(1) | key_type(1) | key_size(2) | key_ACL(6)]
		// Check entire blob header
		if (bytesLeft < 4)
			ISOException.throwIt(SW_INVALID_PARAMETER);
		// Check Blob Encoding - TODO: Encrypted key blob ?
		if (buffer[dataOffset] != BLOB_ENC_PLAIN)
			ISOException.throwIt(SW_UNSUPPORTED_FEATURE);
		dataOffset++; // Skip Blob Encoding
		bytesLeft--;
		byte key_type = buffer[dataOffset];
		dataOffset++; // Skip Key Type
		bytesLeft--;
		short key_size = Util.getShort(buffer, dataOffset);
		dataOffset += (short) 2; // Skip Key Size
		bytesLeft -= (short) 2;
		Util.arrayCopy(buffer, dataOffset, keyACLs, (short) (key_nb * KEY_ACL_SIZE), KEY_ACL_SIZE);
		dataOffset += (short) 6; // Skip ACL
		bytesLeft -= (short) 6;
		/*** Start reading key blob ***/
		short blob_size;
		switch (key_type) {
            case KeyBuilder.TYPE_EC_FP_PUBLIC: // BITCOIN
				// key_blob=[blob_size(2) | pubkey_blob(1+32+32)]
            	if (key_size != 256)
					ISOException.throwIt(key_size);
				ECPublicKey ec_pub_key = (ECPublicKey) getKey(key_nb, key_type, key_size);
				if (bytesLeft < 2)
					ISOException.throwIt(SW_INVALID_PARAMETER);
				blob_size = Util.getShort(buffer, dataOffset);
				if (blob_size != 65) //only uncompressed point 
					ISOException.throwIt(blob_size);
				dataOffset += (short) 2; 
				bytesLeft -= (short) 2;
				if (bytesLeft < (short) (blob_size))
					ISOException.throwIt(SW_INVALID_PARAMETER);
				// others curves parameters are take by default as SECP256k1
				// Satochip default is secp256k1 (over Fp)
				Secp256k1.setCommonCurveParameters(ec_pub_key);
//				ec_pub_key.setFieldFP( SECP256K1_P, (short)0, (short)SECP256K1_P.length);
//				ec_pub_key.setA( SECP256K1_a, (short)0, (short)SECP256K1_a.length);
//				ec_pub_key.setB( SECP256K1_b, (short)0, (short)SECP256K1_b.length);
//				ec_pub_key.setG( SECP256K1_G, (short)0, (short)SECP256K1_G.length);
//				ec_pub_key.setR( SECP256K1_R, (short)0, (short)SECP256K1_R.length);
//				ec_pub_key.setK( SECP256K1_K);
				// set public point
				ec_pub_key.setW(buffer, dataOffset, (short)(blob_size));
				// https://javacard.kenai.com/javadocs/classic/javacard/security/ECPrivateKey.html
				// The plain text data format is big-endian and right-aligned (the least significant bit is the least significant bit of last byte)
				dataOffset += blob_size; 
				bytesLeft -= blob_size;
				break;
			case KeyBuilder.TYPE_EC_FP_PRIVATE: // BITCOIN
				// key_blob=[blob_size(2) | privkey_blob(32)]
            	if (key_size != 256)
					ISOException.throwIt(key_size);
				ECPrivateKey ec_prv_key = (ECPrivateKey) getKey(key_nb, key_type, key_size);
	            if (bytesLeft < 2)
	                    ISOException.throwIt(SW_INVALID_PARAMETER);
	            blob_size = Util.getShort(buffer, dataOffset);
	            if (blob_size != 32) // only bitcoin
	            	ISOException.throwIt(blob_size);
	            dataOffset += (short) 2; 
	            bytesLeft -= (short) 2;
	            if (bytesLeft < (short) (blob_size))
	                ISOException.throwIt(SW_INVALID_PARAMETER);
	            // curves parameters are take by default as SECP256k1
	            // Satochip default is secp256k1 (over Fp)
	            Secp256k1.setCommonCurveParameters(ec_prv_key);
	            // set from secret value
	            ec_prv_key.setS(buffer, dataOffset, blob_size);
	            dataOffset += blob_size; 
	            bytesLeft -= blob_size;
	            break;
			case KeyBuilder.TYPE_RSA_PUBLIC:
				RSAPublicKey rsa_pub_key = (RSAPublicKey) getKey(key_nb, key_type, key_size);
				if (bytesLeft < 2)
					ISOException.throwIt(SW_INVALID_PARAMETER);
				blob_size = Util.getShort(buffer, dataOffset);
				dataOffset += (short) 2; // Skip Mod Size
				bytesLeft -= (short) 2;
				if (bytesLeft < (short) (blob_size + 2))
					ISOException.throwIt(SW_INVALID_PARAMETER);
				rsa_pub_key.setModulus(buffer, dataOffset, blob_size);
				dataOffset += blob_size; // Skip Mod Value
				bytesLeft -= blob_size;
				// bytesLeft already checked in previous if ()
				blob_size = Util.getShort(buffer, dataOffset);
				dataOffset += (short) 2; // Skip Exp Size
				bytesLeft -= (short) 2;
				if (bytesLeft < blob_size)
					ISOException.throwIt(SW_INVALID_PARAMETER);
				rsa_pub_key.setExponent(buffer, dataOffset, blob_size);
				dataOffset += blob_size; // Skip Exp Value
				bytesLeft -= blob_size;
				break;
			case KeyBuilder.TYPE_RSA_PRIVATE:
				RSAPrivateKey rsa_prv_key = (RSAPrivateKey) getKey(key_nb, key_type, key_size);
				if (bytesLeft < 2)
					ISOException.throwIt(SW_INVALID_PARAMETER);
				blob_size = Util.getShort(buffer, dataOffset);
				dataOffset += (short) 2; // Skip Mod Size
				bytesLeft -= (short) 2;
				if (bytesLeft < (short) (blob_size + 2))
					ISOException.throwIt(SW_INVALID_PARAMETER);
				rsa_prv_key.setModulus(buffer, dataOffset, blob_size);
				dataOffset += blob_size; // Skip Mod Value
				bytesLeft -= blob_size;
				// bytesLeft already checked in previous if ()
				blob_size = Util.getShort(buffer, dataOffset);
				dataOffset += (short) 2; // Skip Exp Size
				bytesLeft -= (short) 2;
				if (bytesLeft < blob_size)
					ISOException.throwIt(SW_INVALID_PARAMETER);
				rsa_prv_key.setExponent(buffer, dataOffset, blob_size);
				dataOffset += blob_size; // Skip Exp Value
				bytesLeft -= blob_size;
				break;
			case KeyBuilder.TYPE_RSA_CRT_PRIVATE:
				RSAPrivateCrtKey rsa_prv_key_crt = (RSAPrivateCrtKey) getKey(key_nb, key_type, key_size);
				if (bytesLeft < 2)
					ISOException.throwIt(SW_INVALID_PARAMETER);
				blob_size = Util.getShort(buffer, dataOffset);
				dataOffset += (short) 2; // Skip P Size
				bytesLeft -= (short) 2;
				if (bytesLeft < (short) (blob_size + 2))
					ISOException.throwIt(SW_INVALID_PARAMETER);
				rsa_prv_key_crt.setP(buffer, dataOffset, blob_size);
				dataOffset += blob_size; // Skip P Value
				bytesLeft -= blob_size;
				// bytesLeft ok...
				blob_size = Util.getShort(buffer, dataOffset);
				dataOffset += (short) 2; // Skip Q Size
				bytesLeft -= (short) 2;
				if (bytesLeft < (short) (blob_size + 2))
					ISOException.throwIt(SW_INVALID_PARAMETER);
				rsa_prv_key_crt.setQ(buffer, dataOffset, blob_size);
				dataOffset += blob_size; // Skip Q Value
				bytesLeft -= blob_size;
				// bytesLeft ok...
				blob_size = Util.getShort(buffer, dataOffset);
				dataOffset += (short) 2; // Skip PQ Size
				bytesLeft -= (short) 2;
				if (bytesLeft < (short) (blob_size + 2))
					ISOException.throwIt(SW_INVALID_PARAMETER);
				rsa_prv_key_crt.setPQ(buffer, dataOffset, blob_size);
				dataOffset += blob_size; // Skip PQ Value
				bytesLeft -= blob_size;
				// bytesLeft ok...
				blob_size = Util.getShort(buffer, dataOffset);
				dataOffset += (short) 2; // Skip DP1 Size
				bytesLeft -= (short) 2;
				if (bytesLeft < (short) (blob_size + 2))
					ISOException.throwIt(SW_INVALID_PARAMETER);
				rsa_prv_key_crt.setDP1(buffer, dataOffset, blob_size);
				dataOffset += blob_size; // Skip DP1 Value
				bytesLeft -= blob_size;
				// bytesLeft ok...
				blob_size = Util.getShort(buffer, dataOffset);
				dataOffset += (short) 2; // Skip DQ1 Size
				bytesLeft -= (short) 2;
				if (bytesLeft < blob_size)
					ISOException.throwIt(SW_INVALID_PARAMETER);
				rsa_prv_key_crt.setDQ1(buffer, dataOffset, blob_size);
				dataOffset += blob_size; // Skip DQ1 Value
				bytesLeft -= blob_size;
				break;
			case KeyBuilder.TYPE_DES:
				DESKey des_key = (DESKey) getKey(key_nb, key_type, key_size);
				if (bytesLeft < 2)
					ISOException.throwIt(SW_INVALID_PARAMETER);
				blob_size = Util.getShort(buffer, dataOffset);
				dataOffset += (short) 2; // Skip Key Size
				bytesLeft -= (short) 2;
				if (bytesLeft < blob_size)
					ISOException.throwIt(SW_INVALID_PARAMETER);
				des_key.setKey(buffer, dataOffset);
				dataOffset += blob_size; // Skip Key Value
				bytesLeft -= blob_size;
				break;
			case KeyBuilder.TYPE_AES:
				AESKey aes_key = (AESKey) getKey(key_nb, key_type, key_size);
				if (bytesLeft < 2)
					ISOException.throwIt(SW_INVALID_PARAMETER);
				blob_size = Util.getShort(buffer, dataOffset);
				dataOffset += (short) 2; // Skip Key Size
				bytesLeft -= (short) 2;
				if (bytesLeft < blob_size)
					ISOException.throwIt(SW_INVALID_PARAMETER);
				aes_key.setKey(buffer, dataOffset);
				dataOffset += blob_size; // Skip Key Value
				bytesLeft -= blob_size;
				break;
			default:
				ISOException.throwIt(SW_INCORRECT_ALG);
		}// end switch
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
		
		if (buffer[ISO7816.OFFSET_P2] != (byte) 0x00)
			ISOException.throwIt(SW_INCORRECT_P2);
		short bytesLeft = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
		if (bytesLeft != apdu.setIncomingAndReceive())
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		byte key_nb = buffer[ISO7816.OFFSET_P1];
		if ((key_nb < 0) || (key_nb >= MAX_NUM_KEYS))
			ISOException.throwIt(SW_INCORRECT_P1);
		
		Key key = keys[key_nb];
		if ((key == null) || !key.isInitialized())
			ISOException.throwIt(SW_INCORRECT_P1);
		
		// Enforce Access Control
		if (!authorizeKeyOp(key_nb, ACL_READ))
			ISOException.throwIt(SW_UNAUTHORIZED);
		
		// check type
		byte key_type = key.getType();
		switch(key_type){
		
			case KeyBuilder.TYPE_EC_FP_PRIVATE:
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
		        break;
		        
		    default:
		    	ISOException.throwIt(SW_INCORRECT_ALG);
		}// end switch
	}		

//	private void ExportKey(APDU apdu, byte[] buffer) {
//		if (buffer[ISO7816.OFFSET_P2] != (byte) 0x00)
//			ISOException.throwIt(SW_INCORRECT_P2);
//		short bytesLeft = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
//		if (bytesLeft != apdu.setIncomingAndReceive())
//			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
//		byte key_nb = buffer[ISO7816.OFFSET_P1];
//		if ((key_nb < 0) || (key_nb >= MAX_NUM_KEYS))
//			ISOException.throwIt(SW_INCORRECT_P1);
//		Key key = keys[key_nb];
//		if ((key == null) || !key.isInitialized())
//			ISOException.throwIt(SW_INCORRECT_P1);
//		// Enforce Access Control
//		if (!authorizeKeyOp(key_nb, ACL_READ))
//			ISOException.throwIt(SW_UNAUTHORIZED);
//		// Destroy output object if already exists
//		om.destroyObject(OUT_OBJECT_CLA, OUT_OBJECT_ID, true);
//		// Automatically throws SW_NO_MEMORY_LEFT
//		short base = om.createObjectMax(OUT_OBJECT_CLA, OUT_OBJECT_ID, getCurrentACL(), (short) 0);
//		short buffer_size = om.getSizeFromAddress(base);
//		short avail = buffer_size; // Initially holds buffer size, after is used to check buffer overflow
//		/*** Start reading key blob ***/
//		// Check Blob Encoding
//		if (buffer[ISO7816.OFFSET_CDATA] != BLOB_ENC_PLAIN)
//			ISOException.throwIt(SW_UNSUPPORTED_FEATURE);
//		// No need to check avail for all the key header
//		if (avail < 4)
//			ThrowDeleteObjects(SW_NO_MEMORY_LEFT);
//		mem.setByte(base, BLOB_ENC_PLAIN);
//		base++; // Skip Blob Encoding
//		// avail advanced below
//		byte key_type = key.getType();
//		mem.setByte(base, key_type);
//		base++;
//		// avail advanced below
//		short key_size = key.getSize();
//		mem.setShort(base, key_size);
//		base += (short) 2; // Skip Key Size
//		// keeps into account all the key header
//		avail -= (short) 4;
//		short size;
//		/*
//		 * Maximum size of a BigNumber estimated to be equal to the key size + 2
//		 * bytes for the bignum size itself. TODO: Check if true for DSA, ECC
//		 */
//		short bn_size = (short) (keys[key_nb].getSize() / 8 + 2);
//		switch (key_type) {
//		case KeyBuilder.TYPE_EC_FP_PUBLIC:
//			ECPublicKey ec_pub_key = (ECPublicKey) key;
//			if (avail < bn_size)
//				ThrowDeleteObjects(SW_NO_MEMORY_LEFT);
//			size = ec_pub_key.getW(mem.getBuffer(), (short) (base + 2));
//			mem.setShort(base, size);
//			base += (short) (2 + size); // Skip Modulus Size & Value
//			avail -= (short) (2 + size);
//			break;
//		case KeyBuilder.TYPE_RSA_PUBLIC:
//			RSAPublicKey pub_key = (RSAPublicKey) key;
//			if (avail < bn_size)
//				ThrowDeleteObjects(SW_NO_MEMORY_LEFT);
//			size = pub_key.getModulus(mem.getBuffer(), (short) (base + 2));
//			mem.setShort(base, size);
//			base += (short) (2 + size); // Skip Modulus Size & Value
//			avail -= (short) (2 + size);
//			if (avail < bn_size)
//				ThrowDeleteObjects(SW_NO_MEMORY_LEFT);
//			size = pub_key.getExponent(mem.getBuffer(), (short) (base + 2));
//			mem.setShort(base, size);
//			base += (short) (2 + size); // Skip Exponent Size & Value
//			avail -= (short) (2 + size);
//			break;
//		case KeyBuilder.TYPE_RSA_PRIVATE:
//			RSAPrivateKey prv_key = (RSAPrivateKey) key;
//			if (avail < bn_size)
//				ISOException.throwIt(SW_NO_MEMORY_LEFT);
//			size = prv_key.getModulus(mem.getBuffer(), (short) (base + 2));
//			mem.setShort(base, size);
//			base += (short) (2 + size); // Skip Modulus Size & Value
//			avail -= (short) (2 + size);
//			if (avail < bn_size)
//				ThrowDeleteObjects(SW_NO_MEMORY_LEFT);
//			size = prv_key.getExponent(mem.getBuffer(), (short) (base + 2));
//			mem.setShort(base, size);
//			base += (short) (2 + size); // Skip Exponent Size & Value
//			avail -= (short) (2 + size);
//			break;
//		case KeyBuilder.TYPE_RSA_CRT_PRIVATE:
//			RSAPrivateCrtKey prv_key_crt = (RSAPrivateCrtKey) key;
//			if (avail < bn_size)
//				ThrowDeleteObjects(SW_NO_MEMORY_LEFT);
//			size = prv_key_crt.getP(mem.getBuffer(), (short) (base + 2));
//			mem.setShort(base, size);
//			base += (short) (2 + size); // Skip P Size & Value
//			avail -= (short) (2 + size);
//			if (avail < bn_size)
//				ThrowDeleteObjects(SW_NO_MEMORY_LEFT);
//			size = prv_key_crt.getQ(mem.getBuffer(), (short) (base + 2));
//			mem.setShort(base, size);
//			base += (short) (2 + size); // Skip Q Size & Value
//			avail -= (short) (2 + size);
//			if (avail < bn_size)
//				ThrowDeleteObjects(SW_NO_MEMORY_LEFT);
//			size = prv_key_crt.getPQ(mem.getBuffer(), (short) (base + 2));
//			mem.setShort(base, size);
//			base += (short) (2 + size); // Skip PQ Size & Value
//			avail -= (short) (2 + size);
//			if (avail < bn_size)
//				ThrowDeleteObjects(SW_NO_MEMORY_LEFT);
//			size = prv_key_crt.getDP1(mem.getBuffer(), (short) (base + 2));
//			mem.setShort(base, size);
//			base += (short) (2 + size); // Skip DP1 Size & Value
//			avail -= (short) (2 + size);
//			if (avail < bn_size)
//				ThrowDeleteObjects(SW_NO_MEMORY_LEFT);
//			size = prv_key_crt.getDQ1(mem.getBuffer(), (short) (base + 2));
//			mem.setShort(base, size);
//			base += (short) (2 + size); // Skip DQ1 Size & Value
//			avail -= (short) (2 + size);
//			break;
//		case KeyBuilder.TYPE_DES:
//			DESKey des_key = (DESKey) key;
//			/* For a DES Key, bn_size contains the exact key length + 2 */
//			if (avail < bn_size)
//				ThrowDeleteObjects(SW_NO_MEMORY_LEFT);
//			size = des_key.getKey(mem.getBuffer(), (short) (base + 2));
//			mem.setShort(base, size);
//			base += (short) (2 + size); // Skip P Size & Value
//			avail -= (short) (2 + size);
//			break;
//		default:
//			ISOException.throwIt(SW_INVALID_PARAMETER);
//		}
//		// Eventually clamp buffer to make the export object the exact
//		// size of the exported key blob
//		om.clampObject(OUT_OBJECT_CLA, OUT_OBJECT_ID, (short) (buffer_size - avail));
//	}

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
		byte pin_nb = buffer[ISO7816.OFFSET_P1];
		byte num_tries = buffer[ISO7816.OFFSET_P2];
		/* Check that Identity n.0 is logged */
		if ((create_pin_ACL == (byte) 0xFF)
				|| (((logged_ids & create_pin_ACL) == (short) 0x0000) && (create_pin_ACL != (byte) 0x00)))
			ISOException.throwIt(SW_UNAUTHORIZED);
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
		// At least 1 charachter for each PIN code
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

	/**
	 * This function creates an object that will be identified by the provided object ID.
	 * The object’s space and name will be allocated until deleted using MSCDeleteObject.
	 * The object will be allocated upon the card's memory heap. 
	 * Object creation is only allowed if the object ID is available and logged in
	 * identity(-ies) have sufficient privileges to create objects.
	 *  
	 * ins: 0x5A
	 * p1: 0x00
	 * p2: 0x00
	 * data: [object_id(4b) | object_size(4b) | object_ACL(6b)] 
	 * 		where ACL is Read-Write-Delete
	 * return: none
	 */
	private void CreateObject(APDU apdu, byte[] buffer) {
		short bytesLeft = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
		if (bytesLeft != apdu.setIncomingAndReceive())
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		if ((create_object_ACL == (byte) 0xFF)
				|| (((logged_ids & create_object_ACL) == (short) 0x0000) && (create_object_ACL != (byte) 0x00)))
			ISOException.throwIt(SW_UNAUTHORIZED);
		// ID + Size + ACL = 14 bytes
		if (bytesLeft != (short) (4 + 4 + ObjectManager.OBJ_ACL_SIZE))
			ISOException.throwIt(SW_INVALID_PARAMETER);
		if (buffer[ISO7816.OFFSET_P1] != 0x00)
			ISOException.throwIt(SW_INCORRECT_P1);
		if (buffer[ISO7816.OFFSET_P2] != 0x00)
			ISOException.throwIt(SW_INCORRECT_P2);
		// Retrieve Object ID.
		short obj_class = Util.getShort(buffer, ISO7816.OFFSET_CDATA);
		short obj_id = Util.getShort(buffer, (short) (ISO7816.OFFSET_CDATA + (short) 2));
		// Check if object exists
		if (om.exists(obj_class, obj_id))
			ISOException.throwIt(SW_OBJECT_EXISTS);
		// Check if object size in supported range: M.S.Word must be 0x0000 AND
		// M.S.Bit of L.S.Word must be 0
		if ((Util.getShort(buffer, (short) (ISO7816.OFFSET_CDATA + 4)) != 0x0000)
				|| (buffer[(short) (ISO7816.OFFSET_CDATA + 6)] < 0))
			ISOException.throwIt(SW_NO_MEMORY_LEFT);
		// Check for zero size
		if (Util.getShort(buffer, (short) (ISO7816.OFFSET_CDATA + 6)) == 0x0000)
			ISOException.throwIt(SW_INVALID_PARAMETER);
		// Actually create object
		om.createObject(obj_class, obj_id,
		// Skip 2 M.S.Bytes of Size (only handle short sizes)
				Util.getShort(buffer, (short) (ISO7816.OFFSET_CDATA + 6)), buffer, (short) (ISO7816.OFFSET_CDATA + 8));
	}

	/**
	 * This function deletes the object identified by the provided object ID. The object’s
	 * space and name will be removed from the heap and made available for other objects.
	 * The zero flag denotes whether the object’s memory should be zeroed after
	 * deletion. This kind of deletion is recommended if object was storing sensitive data.
	 *   
	 * ins: 0x52
	 * p1: 0x00
	 * p2: 0x00 or 0x01 for secure erasure 
	 * data: [object_id(4b)] 
	 * return: none
	 */
	private void DeleteObject(APDU apdu, byte[] buffer) {
		if (buffer[ISO7816.OFFSET_P1] != (byte) 0x00)
			ISOException.throwIt(SW_INCORRECT_P1);
		if ((buffer[ISO7816.OFFSET_P2] != (byte) 0x00) && (buffer[ISO7816.OFFSET_P2] != (byte) 0x01))
			ISOException.throwIt(SW_INCORRECT_P2);
		short bytesLeft = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
		if (bytesLeft != apdu.setIncomingAndReceive())
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		if (bytesLeft != (short) 0x04)
			ISOException.throwIt(SW_INVALID_PARAMETER);
		short obj_class = Util.getShort(buffer, ISO7816.OFFSET_CDATA);
		short obj_id = Util.getShort(buffer, (short) (ISO7816.OFFSET_CDATA + (short) 2));
		// TODO: Here there are 2 object lookups. Optimize, please !
		// (single destroy function with logged_ids param)
		short base = om.getBaseAddress(obj_class, obj_id);
		// Verify that object exists
		if (base == MemoryManager.NULL_OFFSET)
			ISOException.throwIt(SW_OBJECT_NOT_FOUND);
		// Enforce Access Control
		if (!om.authorizeDeleteFromAddress(base, logged_ids))
			ISOException.throwIt(SW_UNAUTHORIZED);
		// Actually delete the object
		om.destroyObject(obj_class, obj_id, buffer[ISO7816.OFFSET_P2] == 0x01);
	}

	/**
	 * This function reads data from an object that has been previously created with 
	 * MSCCreateObject. Object data is read starting from the byte specified by the
	 * Offset parameter. Up to 255 bytes can be transferred with a single APDU. 
	 * If more bytes need to be transferred, then multiple ReadObject commands must 
	 * be used with different offsets. 
	 * Object data will be effectively read only if logged in identity(ies) have 
	 * sufficient privileges for the operation, according to the object’s ACL.
	 *   
 	 * ins: 0x56
	 * p1: 0x00
	 * p2: 0x00 
	 * data: [object_id(4b) | object_offset(4b) | chunk_length(1b)] 
	 * return: [object_data(chunk_length)]
	 */
	private void ReadObject(APDU apdu, byte[] buffer) {
		// Checking P1 & P2
		if (buffer[ISO7816.OFFSET_P1] != (byte) 0x00)
			ISOException.throwIt(SW_INCORRECT_P1);
		if (buffer[ISO7816.OFFSET_P2] != (byte) 0x00)
			ISOException.throwIt(SW_INCORRECT_P2);
		short bytesLeft = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
		if (bytesLeft != apdu.setIncomingAndReceive())
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		if (bytesLeft != (short) 9)
			ISOException.throwIt(SW_INVALID_PARAMETER);
		short obj_class = Util.getShort(buffer, ISO7816.OFFSET_CDATA);
		short obj_id = Util.getShort(buffer, (short) (ISO7816.OFFSET_CDATA + (short) 2));
		// Skip 2 M.S.Bytes of the offset
		short offset = Util.getShort(buffer, (short) (ISO7816.OFFSET_CDATA + (short) 6));
		short size = Util.makeShort((byte) 0x00, buffer[(short) ISO7816.OFFSET_CDATA + (short) 8]);
		short base = om.getBaseAddress(obj_class, obj_id);
		// Verify that object exists
		if (base == MemoryManager.NULL_OFFSET)
			ISOException.throwIt(SW_INVALID_PARAMETER);
		// Enforce Access Control
		if (!om.authorizeReadFromAddress(base, logged_ids))
			ISOException.throwIt(SW_UNAUTHORIZED);
		/*
		 * Additional checks: buffer overflow protection (prevents reading
		 * memory contents following the object)
		 */
		if ((short) (offset + size) > om.getSizeFromAddress(base))
			ISOException.throwIt(SW_INVALID_PARAMETER);
		// Sending data
		sendData(apdu, mem.getBuffer(), (short) (base + offset), size);
	}

	/**
	 * This function returns the size of an object that has been previously created with 
	 * MSCCreateObject.  
	 *   
 	 * ins: 0x57
	 * p1: 0x00
	 * p2: 0x00 
	 * data: [object_id(4b)] 
	 * return: [object_size(2b)]
	 */
	private void GetObjectSize(APDU apdu, byte[] buffer) {
		// Checking P1 & P2
		if (buffer[ISO7816.OFFSET_P1] != (byte) 0x00)
			ISOException.throwIt(SW_INCORRECT_P1);
		if (buffer[ISO7816.OFFSET_P2] != (byte) 0x00)
			ISOException.throwIt(SW_INCORRECT_P2);
		short bytesLeft = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
		if (bytesLeft != apdu.setIncomingAndReceive())
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		if (bytesLeft != (short) 4)
			ISOException.throwIt(SW_INVALID_PARAMETER);
		short obj_class = Util.getShort(buffer, ISO7816.OFFSET_CDATA);
		short obj_id = Util.getShort(buffer, (short) (ISO7816.OFFSET_CDATA + (short) 2));
		short base = om.getBaseAddress(obj_class, obj_id);
		// Verify that object exists
		if (base == MemoryManager.NULL_OFFSET)
			ISOException.throwIt(SW_INVALID_PARAMETER);
		// get object size
		short obj_size= om.getSizeFromAddress(base);
		// Fill the buffer
		Util.setShort(buffer, (short) 0, obj_size);
		// Send response
		apdu.setOutgoingAndSend((short) 0, (short) 2);
	}
	
	/**
	 * This function (over-)writes data to an object that has been previously created with
	 * CreateObject. Provided Object Data is stored starting from the byte specified
	 * by the Offset parameter. The size of provided object data must be exactly (Data
	 * Length – 8) bytes. Provided offset value plus the size of provided Object Data
	 * must not exceed object size. 
	 * Up to 246 bytes can be transferred with a single APDU. If more bytes need to be
	 * transferred, then multiple WriteObject commands must be used with different offsets.
	 * 
	 * ins: 0x54
	 * p1: 0x00
	 * p2: 0x00 
	 * data: [object_id(4b) | object_offset(4b) | data_size(1b) | data] 
	 * return: none
	 */
	private void WriteObject(APDU apdu, byte[] buffer) {
		// Checking P1 & P2
		if (buffer[ISO7816.OFFSET_P1] != (byte) 0x00)
			ISOException.throwIt(SW_INCORRECT_P1);
		if (buffer[ISO7816.OFFSET_P2] != (byte) 0x00)
			ISOException.throwIt(SW_INCORRECT_P2);
		short bytesLeft = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
		if (bytesLeft != apdu.setIncomingAndReceive())
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		short obj_class = Util.getShort(buffer, ISO7816.OFFSET_CDATA);
		short obj_id = Util.getShort(buffer, (short) (ISO7816.OFFSET_CDATA + 2));
		// Skip 2 M.S.Bytes of the offset
		short offset = Util.getShort(buffer, (short) (ISO7816.OFFSET_CDATA + 6));
		short size = Util.makeShort((byte) 0x00, buffer[(short) (ISO7816.OFFSET_CDATA + 8)]);
		short base = om.getBaseAddress(obj_class, obj_id);
		// Verify that object exists
		if (base == MemoryManager.NULL_OFFSET)
			ISOException.throwIt(SW_INVALID_PARAMETER);
		// Enforce Access Control
		if (!om.authorizeWriteFromAddress(base, logged_ids))
			ISOException.throwIt(SW_UNAUTHORIZED);
		/*
		 * Additional checks: buffer overflow protection (prevents writing
		 * memory contents following the object)
		 */
		if ((short) (offset + size) > om.getSizeFromAddress(base))
			ISOException.throwIt(SW_INVALID_PARAMETER);
		// Update object data
		mem.setBytes(base, offset, buffer, (short) (ISO7816.OFFSET_CDATA + 9), size);
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
	 * This function returns a list of current objects and their properties including id,
	 * size, and access control. This function must be initially called with the reset
	 * option. The function only returns one object information at a time and must be
	 * called in repetition until SW_SUCCESS is returned with no further data.
	 * Applications cannot rely on any special ordering of the sequence of returned objects. 
	 * 
	 *  ins: 0x58
	 *  p1: 0x00 (reset and get first entry) or 0x01 (next entry)
	 *  p2: 0x00 
	 *  data: none
	 *  return: [object_id(4b) | object_size(4b) | object_ACL(6b)]
	 */
	private void ListObjects(APDU apdu, byte[] buffer) {
		// Checking P1 & P2
		if (buffer[ISO7816.OFFSET_P2] != (byte) 0x00)
			ISOException.throwIt(SW_INCORRECT_P2);
		byte expectedBytes = (byte) (buffer[ISO7816.OFFSET_LC]);
		if (expectedBytes < ObjectManager.RECORD_SIZE)
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		boolean found = false; // Suppress compiler warning
		if (buffer[ISO7816.OFFSET_P1] == LIST_OPT_RESET)
			found = om.getFirstRecord(buffer, (short) 0);
		else if (buffer[ISO7816.OFFSET_P1] != LIST_OPT_NEXT)
			ISOException.throwIt(SW_INCORRECT_P1);
		else
			found = om.getNextRecord(buffer, (short) 0);
		if (found)
			apdu.setOutgoingAndSend((short) 0, (short) ObjectManager.RECORD_SIZE);
		else
			ISOException.throwIt(SW_SEQUENCE_END);
	}
	
	/**
	 * This function returns a list of current keys and their properties including id, type,
	 * size, partner, and access control. This function is initially called with the reset
	 * sequence set for sequence type. The function only returns one object id at a time
	 * and must be called in repetition until SW_SUCCESS is returned. 
	 * 
	 *  ins: 0x3A
	 *  p1: 0x00 (reset and get first entry) or 0x01 (next entry)
	 *  p2: 0x00 
	 *  data: none
	 *  return: [key_num(1b) | key_type(1b) | key_partner(1b) | key_size(2b) | key_ACL(6b)]
	 */
	private void ListKeys(APDU apdu, byte[] buffer) {
		// Checking P2
		if (buffer[ISO7816.OFFSET_P2] != (byte) 0x00)
			ISOException.throwIt(SW_INCORRECT_P2);
		short expectedBytes = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
		if (expectedBytes != (short) 0x0B)
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		if (buffer[ISO7816.OFFSET_P1] == LIST_OPT_RESET)
			key_it = (byte) 0;
		else if (buffer[ISO7816.OFFSET_P1] != LIST_OPT_NEXT)
			ISOException.throwIt(SW_INCORRECT_P1);
		while ((key_it < MAX_NUM_KEYS) && ((keys[key_it] == null) || !keys[key_it].isInitialized()))
			key_it++;
		if (key_it < MAX_NUM_KEYS) {
			Key key = keys[key_it];
			buffer[(short) 0] = key_it;
			buffer[(short) 1] = key.getType();// getKeyType(key);
			buffer[(short) 2] = (byte) 0xFF; // No partner information available
			Util.setShort(buffer, (short) 3, key.getSize());
			Util.arrayCopyNonAtomic(keyACLs, (short) (key_it * KEY_ACL_SIZE), buffer, (short) 5, KEY_ACL_SIZE);
			// Advance iterator
			key_it++;
			apdu.setOutgoingAndSend((short) 0, (short) (5 + KEY_ACL_SIZE));
		}
	}

//	private void GetChallenge(APDU apdu, byte[] buffer) {
//		if (buffer[ISO7816.OFFSET_P1] != (byte) 0x00)
//			ISOException.throwIt(SW_INCORRECT_P1);
//		short bytesLeft = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
//		if (bytesLeft != apdu.setIncomingAndReceive())
//			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
//		if (bytesLeft < 4)
//			ISOException.throwIt(SW_INVALID_PARAMETER);
//		short size = Util.getShort(buffer, ISO7816.OFFSET_CDATA);
//		short seed_size = Util.getShort(buffer, (short) (ISO7816.OFFSET_CDATA + 2));
//		if (bytesLeft != (short) (seed_size + 4))
//			ISOException.throwIt(SW_INVALID_PARAMETER);
//		byte data_loc = buffer[ISO7816.OFFSET_P2];
//		if ((data_loc != DL_APDU) && (data_loc != DL_OBJECT))
//			ISOException.throwIt(SW_INVALID_PARAMETER);
//		if (randomData == null)
//			randomData = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
//		if (seed_size != (short) 0x0000)
//			randomData.setSeed(buffer, (short) (ISO7816.OFFSET_CDATA + 4), seed_size);
//		// Allow size = 0 for only seeding purposes
//		if (size != (short) 0x0000) {
//			// Automatically throws exception if no memory
//			short base = om.createObject(OUT_OBJECT_CLA, OUT_OBJECT_ID, (short) (size + 2), getRestrictedACL(),
//					(short) 0);
//			mem.setShort(base, size);
//			randomData.generateData(mem.getBuffer(), (short) (base + 2), size);
//			/*
//			 * Remember that out object contains getChallenge data (to avoid
//			 * attacks pretending to write the out object before extAuth)
//			 */
//			getChallengeDone = true;
//			// Actually return data in APDU only if DL_APDU specified.
//			if (data_loc == DL_APDU) {
//				sendData(apdu, mem.getBuffer(), base, (short) (size + 2));
//				/*
//				 * Don't destroy out object ! Generated data is needed in
//				 * ExtAuth !
//				 */
//				/* Not if running without external authentication */
//				om.destroyObject(OUT_OBJECT_CLA, OUT_OBJECT_ID, true);
//			}
//		}
//	}
//
//	private void ExternalAuthenticate(APDU apdu, byte[] buffer) {
//		if (buffer[ISO7816.OFFSET_P2] != (byte) 0x00)
//			ISOException.throwIt(SW_INCORRECT_P2);
//		short bytesLeft = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
//		if (bytesLeft != apdu.setIncomingAndReceive())
//			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
//		byte key_nb = buffer[ISO7816.OFFSET_P1];
//		if ((key_nb < 0) || (key_nb >= MAX_NUM_AUTH_KEYS) || (keys[key_nb] == null))
//			ISOException.throwIt(SW_INCORRECT_P1);
//		if (bytesLeft < 3)
//			ISOException.throwIt(SW_INVALID_PARAMETER);
//		/* Verify that a GetChallenge has been issued */
//		if (!getChallengeDone)
//			ISOException.throwIt(SW_OPERATION_NOT_ALLOWED);
//		/*
//		 * Clear getChallengeDone flag getChallengeDone = false; /* Retrieve
//		 * getChallenge() data position and check it
//		 */
//		short chall_base = om.getBaseAddress(OUT_OBJECT_CLA, OUT_OBJECT_ID);
//		if (chall_base == MemoryManager.NULL_OFFSET)
//			ISOException.throwIt(SW_OPERATION_NOT_ALLOWED);
//		short obj_size = om.getSizeFromAddress(chall_base);
//		if (obj_size < 3)
//			ISOException.throwIt(SW_INVALID_PARAMETER);
//		short chall_size = mem.getShort(chall_base);
//		/* Actually GetChallenge() creates an object of exact size */
//		if (obj_size != (short) (2 + chall_size))
//			ISOException.throwIt(SW_INVALID_PARAMETER);
//		byte ciph_mode = buffer[ISO7816.OFFSET_CDATA];
//		byte ciph_dir = buffer[(short) (ISO7816.OFFSET_CDATA + 1)];
//		byte[] src_buffer; /* The buffer of encrypted data */
//		short src_offset; /* The offset of encrypted data in src_buffer[] */
//		short src_avail; /* The available encrypted data (+ size) */
//		switch (buffer[(short) (ISO7816.OFFSET_CDATA + 2)]) {
//		case DL_APDU:
//			src_buffer = buffer;
//			src_offset = (short) (ISO7816.OFFSET_CDATA + 3);
//			src_avail = (short) (bytesLeft - 3);
//			break;
//		case DL_OBJECT:
//			src_offset = om.getBaseAddress(IN_OBJECT_CLA, IN_OBJECT_ID);
//			if (src_offset == MemoryManager.NULL_OFFSET)
//				ISOException.throwIt(SW_OBJECT_NOT_FOUND);
//			src_buffer = mem.getBuffer();
//			src_avail = om.getSizeFromAddress(src_offset);
//		default:
//			ISOException.throwIt(SW_INVALID_PARAMETER);
//			return; // Suppress compiler warning
//		}
//		if (src_avail < 2)
//			ISOException.throwIt(SW_INVALID_PARAMETER);
//		short size = Util.getShort(src_buffer, src_offset);
//		if (src_avail < (short) (size + 2))
//			ISOException.throwIt(SW_INVALID_PARAMETER);
//		// Null key already checked above
//		Key key = keys[key_nb];
//		// Check if identity is actually blocked
//		if (keyTries[key_nb] == (byte) 0)
//			ISOException.throwIt(SW_IDENTITY_BLOCKED);
//		byte key_type = key.getType();
//		boolean result = false;
//		switch (ciph_dir) {
//		case Cipher.MODE_DECRYPT:
//			byte jc_ciph_alg;
//			switch (ciph_mode) {
//			case Cipher.ALG_RSA_NOPAD:
//				if (key_type != KeyBuilder.TYPE_RSA_PUBLIC)
//					ISOException.throwIt(SW_INVALID_PARAMETER);
//				jc_ciph_alg = Cipher.ALG_RSA_NOPAD;
//				break;
//			case Cipher.ALG_RSA_PKCS1:
//				if (key_type != KeyBuilder.TYPE_RSA_PUBLIC)
//					ISOException.throwIt(SW_INVALID_PARAMETER);
//				jc_ciph_alg = Cipher.ALG_RSA_PKCS1;
//				break;
//			case Cipher.ALG_DES_CBC_NOPAD:
//				if (key_type != KeyBuilder.TYPE_DES)
//					ISOException.throwIt(SW_INVALID_PARAMETER);
//				jc_ciph_alg = Cipher.ALG_DES_CBC_NOPAD;
//				break;
//			case Cipher.ALG_DES_ECB_NOPAD:
//				if (key_type != KeyBuilder.TYPE_DES)
//					ISOException.throwIt(SW_INVALID_PARAMETER);
//				jc_ciph_alg = Cipher.ALG_DES_ECB_NOPAD;
//				break;
//			default:
//				ISOException.throwIt(SW_INVALID_PARAMETER);
//				return; // Suppress compiler warning
//			}
//			Cipher ciph = getCipher(key_nb, jc_ciph_alg);
//			ciph.init(key, Cipher.MODE_DECRYPT);
//			// Create temporary buffer
//			short temp = mem.alloc(chall_size);
//			if (temp == MemoryManager.NULL_OFFSET)
//				ISOException.throwIt(SW_NO_MEMORY_LEFT);
//			short written_bytes = ciph.doFinal(src_buffer, (short) (src_offset + 2), size, mem.getBuffer(), temp);
//			/*
//			 * JC specifies that, when decrypting, padding bytes are cut out *
//			 * so after a decrypt we should get the same size as the challenge*
//			 * and they should be less than provided encrypted data
//			 */
//			if ((written_bytes == chall_size)
//					&& (Util.arrayCompare(mem.getBuffer(), temp, mem.getBuffer(), (short) (chall_base + 2), chall_size) == (byte) 0))
//				result = true;
//			sendData(apdu, mem.getBuffer(), temp, written_bytes);
//			mem.free(temp);
//			break;
//		case Signature.MODE_VERIFY:
//			byte jc_sign_alg;
//			switch (ciph_mode) {
//			case Signature.ALG_DSA_SHA:
//				if (key_type != KeyBuilder.TYPE_DSA_PUBLIC)
//					ISOException.throwIt(SW_INVALID_PARAMETER);
//				jc_sign_alg = Signature.ALG_DSA_SHA;
//				break;
//			default:
//				ISOException.throwIt(SW_INVALID_PARAMETER);
//				return; // Suppress compiler warning
//			}
//			Signature sign = getSignature(key_nb, jc_sign_alg);
//			sign.init(key, Signature.MODE_VERIFY);
//			if (sign.verify(mem.getBuffer(), (short) (chall_base + 2), chall_size, src_buffer,
//					(short) (src_offset + 2), size))
//				result = true;
//			break;
//		default:
//			ISOException.throwIt(SW_INVALID_PARAMETER);
//		}
//		if (result) {
//			LoginStrongIdentity(key_nb);
//			// Reset try counter
//			keyTries[key_nb] = MAX_KEY_TRIES;
//			om.destroyObject(IN_OBJECT_CLA, IN_OBJECT_ID, true);
//			om.destroyObject(OUT_OBJECT_CLA, OUT_OBJECT_ID, true);
//		} else {
//			// Decrease try counter
//			keyTries[key_nb]--;
//			LogoutIdentity((byte) (key_nb + 8));
//			om.destroyObject(IN_OBJECT_CLA, IN_OBJECT_ID, true);
//			om.destroyObject(OUT_OBJECT_CLA, OUT_OBJECT_ID, true);
//			ISOException.throwIt(SW_AUTH_FAILED);
//		}
//	}

	/**
	 * This function retrieves general information about the Applet running on the smart
	 * card, and useful information about the status of current session, such as object
	 * memory information, currently used number of keys and PIN codes, currently
	 * logged in identities, etc…
	 *  
	 *  ins: 0x3C
	 *  p1: 0x00 
	 *  p2: 0x00 
	 *  data: none
	 *  return: [versions(4b) | secure_memory(4b) | memory(4b) | nb_PIN(1b) | nb_keys(1b) | logged_id(2b)]
	 */
	private void GetStatus(APDU apdu, byte[] buffer) {
		if (buffer[ISO7816.OFFSET_P1] != (byte) 0x00)
			ISOException.throwIt(SW_INCORRECT_P1);
		if (buffer[ISO7816.OFFSET_P2] != (byte) 0x00)
			ISOException.throwIt(SW_INCORRECT_P2);
		short pos = (short) 0;
		buffer[pos++] = (byte) PROTOCOL_MAJOR_VERSION; // Major Card Edge Protocol version n.
		buffer[pos++] = (byte) PROTOCOL_MINOR_VERSION; // Minor Card Edge Protocol version n.
		buffer[pos++] = (byte) APPLET_MAJOR_VERSION; // Major Applet version n.
		buffer[pos++] = (byte) APPLET_MINOR_VERSION; // Minor Applet version n.
		Util.setShort(buffer, pos, (short) bip32_mem.getBuffer().length); // Total secure mem 
		pos += (short) 2;
		Util.setShort(buffer, pos, (short) mem.getBuffer().length); // Total mem
		// L.S.
		pos += (short) 2;
		Util.setShort(buffer, pos, bip32_mem.freemem()); // secure mem 
		pos += (short) 2;
		Util.setShort(buffer, pos, mem.freemem()); // Free mem
		pos += (short) 2;
		byte cnt = (byte) 0;
		for (short i = 0; i < pins.length; i++)
			if (pins[i] != null)
				cnt++;
		buffer[pos++] = cnt; // Number of used PINs
		cnt = (byte) 0;
		for (short i = 0; i < keys.length; i++)
			if (keys[i] != null)
				cnt++;
		buffer[pos++] = cnt; // Number of used Keys
		Util.setShort(buffer, pos, logged_ids); // Logged ids
		pos += (short) 2;
		apdu.setOutgoingAndSend((short) 0, pos);
	}
	
//	private void computeSha512(APDU apdu, byte[] buffer) {
//		if (buffer[ISO7816.OFFSET_P1] != (byte) 0x00)
//			ISOException.throwIt(SW_INCORRECT_P1);
//		if (buffer[ISO7816.OFFSET_P2] != (byte) 0x00)
//			ISOException.throwIt(SW_INCORRECT_P2);
//		//short avail = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
//		short avail2 = apdu.setIncomingAndReceive();
//		
//		sha512.reset();
//		//sha512.doFinal(data, (short) 0, avail2, buffer, (short)0);
//		sha512.doFinal(buffer, (short) ISO7816.OFFSET_CDATA, avail2, buffer, (short)0);
//		
//		apdu.setOutgoingAndSend((short) 0, Sha2.SHA512_DIGEST_LENGTH);
//	}

	private void computeHmac(APDU apdu, byte[] buffer) {
		if (buffer[ISO7816.OFFSET_P1] != (byte)20 && buffer[ISO7816.OFFSET_P1] != (byte)64)
			ISOException.throwIt(SW_INCORRECT_P1);
		if (buffer[ISO7816.OFFSET_P2] != (byte) 0x00)
			ISOException.throwIt(SW_INCORRECT_P2);
		short avail = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
		if (apdu.setIncomingAndReceive() != avail)
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		
		short pos= ISO7816.OFFSET_CDATA;//apdu.getOffsetCdata(); //(short) ISO7816.OFFSET_CDATA;
		short key_size=Util.getShort(buffer, pos);
		pos+=2;
		pos+=key_size;
		short msg_size=Util.getShort(buffer, pos);
		pos+=2;
		short hashSize=0;
		if (buffer[ISO7816.OFFSET_P1]==(byte)20)
			hashSize= HmacSha160.computeHmacSha160(buffer, (short)(ISO7816.OFFSET_CDATA+2), key_size, buffer, pos, msg_size, buffer, (short)0);
		else if (buffer[ISO7816.OFFSET_P1]==(byte)64)
			hashSize= HmacSha512.computeHmacSha512(buffer, (short)(ISO7816.OFFSET_CDATA+2), key_size, buffer, pos, msg_size, buffer, (short)0);
		apdu.setOutgoingAndSend((short) 0, hashSize);
		return;
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
	 *  p1: 0x00 
	 *  p2: 0x00 
	 *  data: [seed_ACL(6b) | seed_size(1b) | seed_data]
	 *  return: [coordx_size(2b) | coordx | sig_size(2b) | sig]
	 */
	private void importBIP32Seed(APDU apdu, byte[] buffer){
		
		if (buffer[ISO7816.OFFSET_P1] != (byte) 0x00)
			ISOException.throwIt(SW_INCORRECT_P1);
		if (buffer[ISO7816.OFFSET_P2] != (byte) 0x00)
			ISOException.throwIt(SW_INCORRECT_P2);
		short bytesLeft = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
		if (bytesLeft != apdu.setIncomingAndReceive())
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);	
		
		/* Check that logged identities are allowed to create seed*/
		if ((create_key_ACL == (byte) 0xFF)
				|| (((logged_ids & create_key_ACL) == (short) 0x0000) && (create_key_ACL != (byte) 0x00)))
			ISOException.throwIt(SW_UNAUTHORIZED);
		
		// if seed is already initialized, check that logged identities are allowed to rewwrite seed (and master key)
		if (bip32_seeded && !authorizeKeyOp(bip32_masterACL, ACL_WRITE))
			ISOException.throwIt(SW_UNAUTHORIZED);
		
		// buffer data = [6-byte ACL | 1-byte seed size (in byte) | seed data]
		// get keyACL 
		short offset= (short)ISO7816.OFFSET_CDATA;
		Util.arrayCopyNonAtomic(buffer, offset, bip32_masterACL, (short)0, (short)KEY_ACL_SIZE);
		offset+= KEY_ACL_SIZE;
		
		// get seed bytesize (max 64 bytes)
		byte bip32_seedsize = buffer[offset];
		offset++;
		if (bip32_seedsize <0 || bip32_seedsize>64)
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		
		// if seed was already defined, we must clear all related objects!!
		short nb_deleted=0;
		if (bip32_seeded){
			nb_deleted= clearAllBip32ExtendedKey(recvBuffer, (short)0);}
		
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
        short coordx_size = keyAgreement.generateSecret(Secp256k1.SECP256K1, Secp256k1.OFFSET_SECP256K1_G, (short) 65, buffer, (short)2); // compute x coordinate of public key as k*G
        Util.setShort(buffer, (short)0, coordx_size);
        // self signed public key
        sigECDSA.init(bip32_authentikey, Signature.MODE_SIGN);
        short sign_size= sigECDSA.sign(buffer, (short)0, (short)(coordx_size+2), buffer, (short)(coordx_size+4));
        Util.setShort(buffer, (short)(2+coordx_size), sign_size);
        Util.setShort(buffer, (short)(2+coordx_size+2+sign_size), nb_deleted); 
        
        // return x-coordinate of public key+signature
        // the client can recover full public-key from the signature or
        // by guessing the compression value () and verifying the signature... 
        // buffer= [coordx_size(2) | coordx | sigsize(2) | sig | nb_deleted(2)]
        apdu.setOutgoingAndSend((short) 0, (short)(2+coordx_size+2+sign_size+2));
		
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
	 * The function computes the Bip32 extended key derived from the master key and returns the 
	 * x-coordinate of the public key signed by the authentikey.
	 * Only hardened keys are currently supported!!
	 * Extended key is stored in the chip in a temporary EC key, along with corresponding ACL
	 * Extended key and chaincode is also cached as a Bip32 object is secure memory
	 * 
	 * ins: 0x6D
	 * p1: depth of the extended key (master is depth 0, m/i is depht 1). Max depth is 10
	 * p2: 0x00 (default) or 0xFF (erase all Bip32 objects from secure memory)
	 * data: index path from master to extended key (m/i/j/k/...). 4 bytes per index
	 * 
	 * returns: [coordx_size(2b) | coordx | sig_size(2b) | sig]
	 * 
	 * */
	private void getBIP32ExtendedKey(APDU apdu, byte[] buffer){
		
		// check master key ACL for computation use (derivation)
		// to do: define a more flexible approach based on parent object ACL?
		if (!authorizeKeyOp(bip32_masterACL, ACL_USE))
			ISOException.throwIt(SW_UNAUTHORIZED);
		
		// input 
		short bytesLeft = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
		if (bytesLeft != apdu.setIncomingAndReceive())
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		
		byte bip32_depth = buffer[ISO7816.OFFSET_P1];
		if ((bip32_depth < 1) || (bip32_depth > MAX_BIP32_DEPTH) )
			ISOException.throwIt(SW_INCORRECT_P1);
		if (bytesLeft < 4*bip32_depth)
			ISOException.throwIt(SW_INVALID_PARAMETER);
		
		// DONE: encrypt by default! this field is currently not used (RFU)...
		// TO DO: flag whether to store (save) key as object (currently by default)?
		byte RFU = buffer[ISO7816.OFFSET_P2]; 
		if (RFU==(byte)0xFF && authorizeKeyOp(bip32_masterACL, ACL_WRITE))
			clearAllBip32ExtendedKey(recvBuffer, (short)0);
		
		// check whether the seed is seed is initialized
		if (!bip32_seeded)
			ISOException.throwIt(SW_BIP32_UNINITIALIZED_SEED);
		
		// master key data (usefull as parent's data for key derivation)
		// The method uses a temporary buffer recvBuffer to store the parent and extended key object data:
		// recvBuffer=[ parent_chain_code (32b) | 0x00 | parent_key (32b) | hash(address)(32b) | current_extended_key(32b) | current_chain_code(32b) | parent_pubkey(65b) | bip32_path(40b)]
		// hash(address)= [ index(4b) | unused (16b)| crc (4b) | ANTICOLLISIONHASHTMP(4b)| ANTICOLLISIONHASH(4b)]
	    // parent_pubkey(65b)= [compression_byte(1b) | coord_x (32b) | coord_y(32b)]
		
		bip32_masterchaincode.getKey(recvBuffer, BIP32_OFFSET_PARENT_CHAINCODE);
		bip32_masterkey.getKey(recvBuffer,BIP32_OFFSET_PARENT_KEY); 		
		recvBuffer[BIP32_OFFSET_PARENT_SEPARATOR]=0x00; // separator, also facilitate HMAC derivation
		Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, recvBuffer, BIP32_OFFSET_PATH, (short)(4*bip32_depth));
		short parent_base=MemoryManager.NULL_OFFSET; 
		
		// iterate on indexes provided 
		for (byte i=1; i<=bip32_depth; i++){
						
			//compute SHA of the extended key address up to depth i (only the last bytes are actually used)
			sha256.reset(); 
			sha256.doFinal(recvBuffer, BIP32_OFFSET_PATH, (short)(i*4), recvBuffer, BIP32_OFFSET_INDEX);
			short crc1=Util.getShort(recvBuffer, BIP32_OFFSET_CRC);
			short crc2=Util.getShort(recvBuffer, (short)(BIP32_OFFSET_CRC+2));
			short base=bip32_om.getBaseAddress(crc1, crc2);
			
			while(base!=MemoryManager.NULL_OFFSET){ // there is already an object at this address
				
				//extract anti-collision hash of object
				bip32_mem.getBytes(recvBuffer, BIP32_OFFSET_COLLISIONHASHTMP, base, (short)0, BIP32_ANTICOLLISION_LENGTH); 
				// check whether it is the correct object or just a collision
				if (Util.arrayCompare(recvBuffer, BIP32_OFFSET_COLLISIONHASHTMP, recvBuffer, BIP32_OFFSET_COLLISIONHASH, BIP32_ANTICOLLISION_LENGTH)==0){
					// copy object data to temporary buffer
					bip32_mem.getBytes(recvBuffer, BIP32_OFFSET_COLLISIONHASH, base, (short)0, BIP32_OBJECT_SIZE);
					// exit loop with base pointing to the correct object
					break; 
				}else{ // collision
					// try next crc address until correct object or no object is found...
					Biginteger.add1_carry(recvBuffer, BIP32_OFFSET_CRC, (short) 4);
					crc1=Util.getShort(recvBuffer, BIP32_OFFSET_CRC);
					crc2=Util.getShort(recvBuffer, (short)(BIP32_OFFSET_CRC+2));
					base=bip32_om.getBaseAddress(crc1, crc2);
				}
			} //end of while
			// at this point, either base points to the correct object, of the object does not exist
			
			// create object if no object was found
			if (base==MemoryManager.NULL_OFFSET){
				
				// normal or hardened child?
				byte msb= recvBuffer[(short)(BIP32_OFFSET_PATH+4*(i-1))];
				if ((msb & 0x80)!=0x80){ // normal child
					// we must compute parent's compressed pubkey from privkey
					// check if parent's compression byte is available
					byte compbyte=0x04;
					if (parent_base==MemoryManager.NULL_OFFSET)
						compbyte=bip32_master_compbyte;
					else
						compbyte=bip32_mem.getByte(parent_base, (short)(BIP32_OBJECT_SIZE-1));
					
					// compute coord x from privkey 
					bip32_extendedkey.setS(recvBuffer, BIP32_OFFSET_PARENT_KEY, BIP32_KEY_SIZE);
					keyAgreement.init(bip32_extendedkey);
			        keyAgreement.generateSecret(Secp256k1.SECP256K1, Secp256k1.OFFSET_SECP256K1_G, (short) 65, recvBuffer, BIP32_OFFSET_PUBX); 
			        
			        // compute compbyte from coord y if necessary
			        if (compbyte==0x04){
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
						if (parent_base==MemoryManager.NULL_OFFSET)
							bip32_master_compbyte= compbyte;
						else
							bip32_mem.setByte(parent_base, (short)(BIP32_OBJECT_SIZE-1), compbyte);
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
				
				// create object if logged identities have the correct ACL
				// to do: check the object ACL
				// to do: create object for transaction keys in last index (since they are usually used only once)?
				base= bip32_om.createObject(crc1, crc2, BIP32_OBJECT_SIZE, bip32_masterACL, (short) 0);
				// Enforce Access Control
				if (!bip32_om.authorizeWriteFromAddress(base, logged_ids))
					ISOException.throwIt(SW_UNAUTHORIZED);
				// Update object data
				recvBuffer[BIP32_OFFSET_PUB]=0x04;
				bip32_mem.setBytes(base, (short)0, recvBuffer, BIP32_OFFSET_COLLISIONHASH, BIP32_OBJECT_SIZE);
			
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
		Util.arrayCopyNonAtomic(bip32_masterACL, (short)0, bip32_extendedACL, (short)0, KEY_ACL_SIZE); 
		
		// clear recvBuffer
		Util.arrayFillNonAtomic(recvBuffer, BIP32_OFFSET_PARENT_CHAINCODE, BIP32_OFFSET_END, (byte)0);
				
		// compute the corresponding partial public key...
        keyAgreement.init(bip32_extendedkey);
        short coordx_size = keyAgreement.generateSecret(Secp256k1.SECP256K1, Secp256k1.OFFSET_SECP256K1_G, (short) 65, buffer, (short)2); // compute x coordinate of public key as k*G
        Util.setShort(buffer, (short)0, coordx_size);
        
        // self-sign coordx
        sigECDSA.init(bip32_extendedkey, Signature.MODE_SIGN);
        short sign_size= sigECDSA.sign(buffer, (short)0, (short)(coordx_size+2), buffer, (short)(coordx_size+4));
        Util.setShort(buffer, (short)(coordx_size+2), sign_size);
        
        // coordx signed by authentikey
        sigECDSA.init(bip32_authentikey, Signature.MODE_SIGN);
        short sign_size2= sigECDSA.sign(buffer, (short)0, (short)(coordx_size+sign_size+4), buffer, (short)(coordx_size+sign_size+6));
        Util.setShort(buffer, (short)(coordx_size+sign_size+4), sign_size2);
        
        // return x-coordinate of public key+signatures
        // the client can recover full public-key by guessing the compression value () and verifying the signature... 
        // buffer=[coordx_size(2) | coordx | sign_size(2) | self-sign | sign_size(2) | auth_sign]
        apdu.setOutgoingAndSend((short) 0, (short)(coordx_size+sign_size+sign_size2+6));
        
	}// end of getBip32ExtendedKey()	
	
	/**
	 * The function clears all the Bip32 objects from secure memory.
	 * This is done during either Bip32 seed import (when a new seed is imported) or when a new
	 * extended key is computed (when p2 flag 0xFF is invoked).
	 */
	private short clearAllBip32ExtendedKey(byte[] tmpBuffer, short offset){
		
		short nb_deleted=0;
		short obj_cla, obj_id;
		while (bip32_om.getFirstRecord(tmpBuffer, offset)){
			
			// get obj_class and obj_id
			obj_cla= Util.getShort(tmpBuffer, offset);
			obj_id= Util.getShort(tmpBuffer, (short)(offset+2));
			bip32_om.destroyObject(obj_cla, obj_id, true);
			nb_deleted++;
		}
		
		return nb_deleted;
	}
    
    /**
     * This function signs Bitcoin message using std or Bip32 extended key
	 *
     * ins: 0x6E
	 * p1: key number or 0xFF for the last derived Bip32 extended key 
	 * p2: Init-Update-Finalize
	 * data(init): none
	 * data(update/finalize): [chunk_size(2b) | chunk_data]
	 * 
	 * returns(init/update): none
	 * return(finalize): [sig]
	 *
     */
    private void signMessage(APDU apdu, byte[] buffer){
		
		byte key_nb = buffer[ISO7816.OFFSET_P1];
		if ( (key_nb!=(byte)0xFF) && ((key_nb < 0)||(key_nb >= MAX_NUM_KEYS)) )
			ISOException.throwIt(SW_INCORRECT_P1);
		
		byte p2= buffer[ISO7816.OFFSET_P2];
    	if (p2 <= (byte) 0x00 || p2 > (byte) 0x03)
			ISOException.throwIt(SW_INCORRECT_P2);
		short bytesLeft = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
		if (bytesLeft != apdu.setIncomingAndReceive())
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);	
		
		// chek ACL
		if (key_nb==(byte)0xFF && !authorizeKeyOp(bip32_extendedACL, ACL_USE))
			ISOException.throwIt(SW_UNAUTHORIZED);
    	if (key_nb!=(byte)0xFF && !authorizeKeyOp(key_nb, ACL_USE))
			ISOException.throwIt(SW_UNAUTHORIZED);
    	
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
				sha256.doFinal(buffer, (short) offset, chunk_size, buffer, (short) 0);
				sign_flag= false;// reset flag
				
				// set key & sign
		    	if (key_nb==(byte)0xFF)
		    		sigECDSA.init(bip32_extendedkey, Signature.MODE_SIGN);
		    	else{
		    		Key key= keys[key_nb];
		    		if (key.getType()!=KeyBuilder.TYPE_EC_FP_PRIVATE)
		    			ISOException.throwIt(SW_INCORRECT_ALG);
		    		sigECDSA.init(key, Signature.MODE_SIGN);
		    	}
		        short sign_size= sigECDSA.sign(buffer, (short)0, (short)32, buffer, (short)0);
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
	 * data: [msg_size(2b) | msg_data]
	 * 
	 * return: [sig]
	 *
     */
    private void signShortMessage(APDU apdu, byte[] buffer){
		
		byte key_nb = buffer[ISO7816.OFFSET_P1];
		if ( (key_nb!=(byte)0xFF) && ((key_nb < 0)||(key_nb >= MAX_NUM_KEYS)) ) // debug!!
			ISOException.throwIt(SW_INCORRECT_P1);
		if (buffer[ISO7816.OFFSET_P2] != (byte) 0x00)
			ISOException.throwIt(SW_INCORRECT_P2);
		short bytesLeft = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
		if (bytesLeft != apdu.setIncomingAndReceive())
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);	
		
		// chek ACL
		if (key_nb==(byte)0xFF && !authorizeKeyOp(bip32_extendedACL, ACL_USE))
			ISOException.throwIt(SW_UNAUTHORIZED);
    	if (key_nb!=(byte)0xFF && !authorizeKeyOp(key_nb, ACL_USE))
			ISOException.throwIt(SW_UNAUTHORIZED);
    	
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
		Util.arrayCopyNonAtomic(buffer, offset, recvBuffer, recvOffset, msgSize);
		offset+= msgSize;
		recvOffset+= msgSize;
		
		// hash SHA-256
		sha256.reset();
		sha256.doFinal(recvBuffer, (short) 0, recvOffset, recvBuffer, (short) 0);
		        
        // set key & sign
    	if (key_nb==(byte)0xFF)
    		sigECDSA.init(bip32_extendedkey, Signature.MODE_SIGN);
    	else{
    		Key key= keys[key_nb];
    		if (key.getType()!=KeyBuilder.TYPE_EC_FP_PRIVATE)
    			ISOException.throwIt(SW_INCORRECT_ALG);
    		sigECDSA.init(key, Signature.MODE_SIGN);
    	}
    	short sign_size= sigECDSA.sign(recvBuffer, (short)0, (short)32, buffer, (short)0);
        apdu.setOutgoingAndSend((short) 0, sign_size);
    	
    }    
    
//    // mainly for testing...
//    private void setBIP32ExtendedKey(APDU apdu, byte[] buffer){
//    	
//    	// set default private point
//        byte[] key_data={
//                (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
//                (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x01 
//        }; 
//        bip32_extendedkey.setS(key_data, (short)0, BIP32_KEY_SIZE); 
//        
//        // compute the corresponding partial public key...
//        keyAgreement.init(bip32_extendedkey);
//        short coordx_size = keyAgreement.generateSecret(SECP256K1_G, (short) 0, (short) SECP256K1_G.length, buffer, (short)2); // compute x coordinate of public key as k*G
//        Util.setShort(buffer, (short)0, coordx_size);
//        
//        // sign fixed message
//        sigECDSA.init(bip32_extendedkey, Signature.MODE_SIGN);
//        short sign_size= sigECDSA.sign(buffer, (short)0, (short)(coordx_size+2), buffer, (short)(coordx_size+4));
//        Util.setShort(buffer, (short)(coordx_size+2), sign_size);
//        
//        // return x-coordinate of public key+signature
//        // the client can recover full public-key from the signature or
//        // by guessing the compression value () and verifying the signature... 
//        apdu.setOutgoingAndSend((short) 0, (short)(coordx_size+sign_size+4));
//        
//    }
    
    /**
     * This function parses a raw transaction and returns the corresponding double SHA-256
	 * If the Bip32 seed is initialized, the hash is signed with the authentikey.
	 * 
     * ins: 0x71
	 * p1: Init or Process 
	 * p2: 0x00
	 * data: [raw_tx]
	 * 
	 * return: [hash(32b) | needs_confirm(1b) | sig_size(2b) | sig ]
	 *
	 * where:
	 * 		needs_confirm is 0x01 if a hmac-sha1 of the hash must be provided for tx signing 
     */
    private void ParseTransaction(APDU apdu, byte[] buffer){
    	
    	byte p1 = buffer[ISO7816.OFFSET_P1];
        byte p2 = buffer[ISO7816.OFFSET_P2];
        short dataOffset = ISO7816.OFFSET_CDATA;
        short dataRemaining = (short)(buffer[ISO7816.OFFSET_LC] & 0xff);
    	
        if (p1== OP_INIT){
        	// initialize transaction object
        	Transaction.resetTransaction();
        }
        
        // parse the transaction
        byte result = Transaction.parseTransaction(buffer, dataOffset, dataRemaining);
        if (result == Transaction.RESULT_ERROR) {
        	Transaction.resetTransaction();
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        else if (result == Transaction.RESULT_MORE) {
            
        	short offset = 0;
        	// Transaction context
        	Util.arrayCopyNonAtomic(Transaction.ctx, Transaction.TX_I_CURRENT_I, buffer, offset, Transaction.SIZEOF_U32);
        	offset += 4;
        	Util.arrayCopyNonAtomic(Transaction.ctx, Transaction.TX_I_CURRENT_O, buffer, offset, Transaction.SIZEOF_U32);
        	offset += 4;
        	Util.arrayCopyNonAtomic(Transaction.ctx, Transaction.TX_I_SCRIPT_COORD, buffer, offset, Transaction.SIZEOF_U32);
        	offset += 4;
        	Util.arrayCopyNonAtomic(Transaction.ctx, Transaction.TX_A_TRANSACTION_AMOUNT, buffer, offset, Transaction.SIZEOF_AMOUNT);
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
            Util.arrayCopyNonAtomic(Transaction.ctx, Transaction.TX_A_TRANSACTION_AMOUNT, transactionData, OFFSET_TRANSACTION_AMOUNT, (short)8);
            Biginteger.add_carry(transactionData, OFFSET_TRANSACTION_AMOUNT, transactionData, OFFSET_TRANSACTION_TOTAL, (short)8);
            if ((option_flags & HMAC_CHALRESP_2FA)==HMAC_CHALRESP_2FA){
	            if (Biginteger.lessThan(transactionData, OFFSET_TRANSACTION_LIMIT, transactionData, OFFSET_TRANSACTION_AMOUNT, (short)8)){
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
        	Util.arrayCopyNonAtomic(Transaction.ctx, Transaction.TX_I_CURRENT_I, buffer, offset, Transaction.SIZEOF_U32);
        	offset += 4;
        	Util.arrayCopyNonAtomic(Transaction.ctx, Transaction.TX_I_CURRENT_O, buffer, offset, Transaction.SIZEOF_U32);
        	offset += 4;
        	Util.arrayCopyNonAtomic(Transaction.ctx, Transaction.TX_I_SCRIPT_COORD, buffer, offset, Transaction.SIZEOF_U32);
        	offset += 4;
        	Util.arrayCopyNonAtomic(Transaction.ctx, Transaction.TX_A_TRANSACTION_AMOUNT, buffer, offset, Transaction.SIZEOF_AMOUNT);
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
            // buffer= [tx_hash(32) | sign_size(2) | signature | tx context(20 - 46)]
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
	 * data: [hash(32b) | option:hmac(20b)]
	 * 
	 * return: [sig ]
	 *
     */
    private void SignTransaction(APDU apdu, byte[] buffer){
    	
    	byte key_nb = buffer[ISO7816.OFFSET_P1];
		if ( (key_nb!=(byte)0xFF) && ((key_nb < 0) || (key_nb >= MAX_NUM_KEYS)) )
			ISOException.throwIt(SW_INCORRECT_P1);
		
    	short bytesLeft = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
		if (bytesLeft != apdu.setIncomingAndReceive())
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		if (bytesLeft<MessageDigest.LENGTH_SHA_256)
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    	
    	if (key_nb==(byte)0xFF && !authorizeKeyOp(bip32_extendedACL, ACL_USE))
			ISOException.throwIt(SW_UNAUTHORIZED);
    	if (key_nb!=(byte)0xFF && !authorizeKeyOp(key_nb, ACL_USE))
			ISOException.throwIt(SW_UNAUTHORIZED);
    	
    	// check whether the seed is initialized
		if (key_nb==(byte)0xFF && !bip32_seeded)
			ISOException.throwIt(SW_BIP32_UNINITIALIZED_SEED);
		
		// check doublehash value in buffer with cached singlehash value
		sha256.reset();
		sha256.doFinal(transactionData, OFFSET_TRANSACTION_HASH, MessageDigest.LENGTH_SHA_256, recvBuffer, (short)0);
		if ((byte)0 != Util.arrayCompare(buffer, ISO7816.OFFSET_CDATA, recvBuffer, (short)0, MessageDigest.LENGTH_SHA_256))
			ISOException.throwIt(SW_INCORRECT_TXHASH);
		
		// check challenge-response answer if necessary
		if( (option_flags & HMAC_CHALRESP_2FA)==HMAC_CHALRESP_2FA){
			if(	Biginteger.lessThan(transactionData, OFFSET_TRANSACTION_LIMIT, transactionData, OFFSET_TRANSACTION_AMOUNT, (short)8)){
				if (bytesLeft<MessageDigest.LENGTH_SHA_256+MessageDigest.LENGTH_SHA+(short)2)
					ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
				// check flag for 2fa_hmac_chalresp
				short hmac_flags= Util.getShort(buffer, (short)(ISO7816.OFFSET_CDATA+32+2));
				if (hmac_flags!=HMAC_CHALRESP_2FA)
					ISOException.throwIt(SW_INCORRECT_ALG);
				// hmac of 64-bytes msg: (doublesha256(raw_tx) | 32bytes padding)
				Util.arrayFillNonAtomic(recvBuffer, (short)32, (short)32, (byte)0x00);
				HmacSha160.computeHmacSha160(transactionData, OFFSET_TRANSACTION_HMACKEY, (short)20, recvBuffer, (short)0, (short)64, recvBuffer, (short)64);
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
    		Key key= keys[key_nb];
    		if (key.getType()!=KeyBuilder.TYPE_EC_FP_PRIVATE)
    			ISOException.throwIt(SW_INCORRECT_ALG);
    		sigECDSA.init(key, Signature.MODE_SIGN);
    	}
        short sign_size= sigECDSA.sign(transactionData, OFFSET_TRANSACTION_HASH, (short)32, buffer, (short)0);
        apdu.setOutgoingAndSend((short) 0, sign_size);
    	
    }
    
} // end of class JAVA_APPLET

