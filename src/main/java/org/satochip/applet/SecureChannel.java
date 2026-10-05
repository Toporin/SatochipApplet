/*
 * SatoChip Bitcoin Hardware Wallet based on javacard
 * (c) 2015-2025 by Toporin - 16DMCk4WUaHofchAhpMaQS4UPm4urcy2dN
 * Sources available on https://github.com/Toporin
 *
 * Secure channel, extracted from Satochip.java (see the license block there).
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

package org.satochip.applet;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.SystemException;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyAgreement;
import javacard.security.RandomData;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

/**
 * Mandatory secure channel between the client and the applet.
 *
 * The channel is opened with an ECDH key exchange between a client ephemeral key and a
 * card ephemeral key (signed by the authentikey). An AES-128 session key and a 20-byte
 * HMAC-SHA1 key are derived from the shared secret. Commands are then sent encrypted
 * (AES-CBC) and authenticated (HMAC-SHA1), with a monotonic IV counter against replay.
 *
 * Memory: this class only allocates its own session state (sc_buffer, sc_sessionkey). The
 * cipher, the scratch EC key, the crypto engines and the working buffers are shared with
 * the applet and passed to the constructor, so splitting this class out of Satochip costs
 * no RAM. Scratch use: recvBuffer[0..65) and recvBuffer[248..268) (see unwrap()),
 * tmpBuffer[0..sizeout+16) (see wrap()), plus the HmacSha160 internal buffer.
 */
class SecureChannel {

    /** Secure channel status words */
    final static short SW_SECURE_CHANNEL_UNINITIALIZED = (short) 0x9C21;
    final static short SW_SECURE_CHANNEL_WRONG_IV= (short) 0x9C22;
    final static short SW_SECURE_CHANNEL_WRONG_MAC= (short) 0x9C23;

    private final static short COORD_SIZE = (short) 32; // size of a secp256k1 coordinate

    /**
     * Largest plaintext response that wrap() can send: the PKCS#7-padded plaintext must fit in
     * tmpBuffer (256b), and [IV(16b) | size(2b) | ciphertext] in a short R-APDU (256b), i.e. a
     * ciphertext of at most 224 bytes. Handlers returning variable-size data must respect it.
     */
    final static short MAX_WRAP_SIZE = (short) 223;

    private static final byte[] CST_SC = {'s','c','_','k','e','y', 's','c','_','m','a','c'};

    // sc_buffer=[ IV(16b) | mackey(20b) ], where IV=[ random(12b) | counter(4b) ]
    private static final byte OFFSET_SC_IV=0;
    private static final byte OFFSET_SC_IV_RANDOM=OFFSET_SC_IV;
    private static final byte OFFSET_SC_IV_COUNTER=12;
    private static final byte OFFSET_SC_MACKEY=16;
    private static final byte SIZE_SC_MACKEY=20;
    private static final byte SIZE_SC_IV= 16;
    private static final byte SIZE_SC_IV_RANDOM=12;
    private static final byte SIZE_SC_IV_COUNTER=SIZE_SC_IV-SIZE_SC_IV_RANDOM;
    private static final byte SIZE_SC_BUFFER=SIZE_SC_MACKEY+SIZE_SC_IV;

    // session state
    private boolean initialized_secure_channel = false;
    private byte[] sc_buffer;
    private AESKey sc_sessionkey;

    // shared with the applet
    private final Cipher sc_aes128_cbc;
    private final ECPrivateKey ephemeral_privkey;
    private final boolean ephemeral_privkey_transient;
    private final KeyAgreement keyAgreement;
    private final Signature sigECDSA;
    private final RandomData randomData;
    private final ECPrivateKey authentikey_private;
    private final ECPublicKey authentikey_public;
    private final byte[] recvBuffer;
    private final byte[] tmpBuffer;

    /**
     * Must be called from the applet constructor, after the authentikey has been generated.
     *
     * @param ephemeral_privkey scratch EC key, also used by the applet between commands:
     *        the secure channel only needs it during initiate()
     * @param ephemeral_privkey_transient true if the curve parameters of ephemeral_privkey
     *        are lost on deselect/reset and must be set again before use
     */
    SecureChannel(Cipher sc_aes128_cbc, ECPrivateKey ephemeral_privkey, boolean ephemeral_privkey_transient,
            KeyAgreement keyAgreement, Signature sigECDSA, RandomData randomData,
            ECPrivateKey authentikey_private, ECPublicKey authentikey_public,
            byte[] recvBuffer, byte[] tmpBuffer) {
        this.sc_aes128_cbc = sc_aes128_cbc;
        this.ephemeral_privkey = ephemeral_privkey;
        this.ephemeral_privkey_transient = ephemeral_privkey_transient;
        this.keyAgreement = keyAgreement;
        this.sigECDSA = sigECDSA;
        this.randomData = randomData;
        this.authentikey_private = authentikey_private;
        this.authentikey_public = authentikey_public;
        this.recvBuffer = recvBuffer;
        this.tmpBuffer = tmpBuffer;

        try {
            sc_buffer = JCSystem.makeTransientByteArray((short) SIZE_SC_BUFFER, JCSystem.CLEAR_ON_DESELECT);
        } catch (SystemException e) {
            sc_buffer = new byte[SIZE_SC_BUFFER];
        }
        sc_sessionkey = Satochip.buildTransientAES128Key();
    }

    /** Closes the channel (e.g. on applet selection): a new one must be initiated. */
    void close() {
        initialized_secure_channel = false;
    }

    /** Closes the channel and erases the session key (factory reset). */
    void clear() {
        sc_sessionkey.clearKey();
        initialized_secure_channel = false;
    }

    /**
     * This function allows to initiate a Secure Channel
     *
     *  ins: 0x81
     *  p1: 0x00
     *  p2: 0x00
     *  data: [client-pubkey(65b)]
     *  return: [coordx_size(2b) | ephemeralkey_coordx | sig_size(2b) | self_sig | sig2_size(2b) | authentikey_sig | coordx_size(2b) | authentikey_coordx]
     */
    short initiate(byte[] buffer){

        // get client pubkey
        short bytesLeft = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
        if (bytesLeft < (short)65)
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        if (buffer[ISO7816.OFFSET_CDATA] != (byte)0x04)
            ISOException.throwIt(Satochip.SW_INVALID_PARAMETER);
        // check that the client point is on secp256k1 (mitigates invalid-curve attacks via ECDH)
        if (!Secp256k1.isOnCurve(buffer, ISO7816.OFFSET_CDATA, recvBuffer, (short)0))
            ISOException.throwIt(Satochip.SW_INVALID_PARAMETER);

        // generate a new ephemeral key
        if (ephemeral_privkey_transient) {
            Secp256k1.setCommonCurveParameters(ephemeral_privkey);
        }
        randomData.generateData(recvBuffer, (short)0, COORD_SIZE);
        ephemeral_privkey.setS(recvBuffer, (short)0, COORD_SIZE); //random value first

        // compute the shared secret...
        keyAgreement.init(ephemeral_privkey);
        keyAgreement.generateSecret(buffer, ISO7816.OFFSET_CDATA, (short) 65, recvBuffer, (short)0); //pubkey in uncompressed form
        // derive sc_sessionkey & sc_mackey
        HmacSha160.computeHmacSha160(recvBuffer, (short)1, COORD_SIZE, CST_SC, (short)6, (short)6, recvBuffer, (short)33);
        Util.arrayCopyNonAtomic(recvBuffer, (short)33, sc_buffer, OFFSET_SC_MACKEY, SIZE_SC_MACKEY);
        HmacSha160.computeHmacSha160(recvBuffer, (short)1, COORD_SIZE, CST_SC, (short)0, (short)6, recvBuffer, (short)33);
        sc_sessionkey.setKey(recvBuffer,(short)33); // AES-128: 16-bytes key!!
        // erase the shared secret and the derived keys from the scratch buffer
        Util.arrayFillNonAtomic(recvBuffer, (short)0, (short)65, (byte)0);

        //reset IV counter
        Util.arrayFillNonAtomic(sc_buffer, OFFSET_SC_IV, SIZE_SC_IV, (byte) 0);

        // self signed ephemeral pubkey
        keyAgreement.generateSecret(Secp256k1.SECP256K1, Secp256k1.OFFSET_SECP256K1_G, (short) 65, buffer, (short)1); //pubkey in uncompressed form
        Util.setShort(buffer, (short)0, COORD_SIZE);
        sigECDSA.init(ephemeral_privkey, Signature.MODE_SIGN);
        short sign_size= sigECDSA.sign(buffer, (short)0, (short)(COORD_SIZE+2), buffer, (short)(COORD_SIZE+4));
        Util.setShort(buffer, (short)(COORD_SIZE+2), sign_size);
        // the ephemeral private key is not needed anymore (forward secrecy within the card
        // session). A persistent fallback key keeps its value: clearKey() would also erase the
        // curve parameters, which are only set again for transient keys.
        if (ephemeral_privkey_transient) {
            ephemeral_privkey.clearKey();
        }

        // hash signed by authentikey
        short offset= (short)(2+COORD_SIZE+2+sign_size);
        sigECDSA.init(authentikey_private, Signature.MODE_SIGN);
        short sign2_size= sigECDSA.sign(buffer, (short)0, offset, buffer, (short)(offset+2));
        Util.setShort(buffer, offset, sign2_size);
        offset+=(short)(2+sign2_size);

        // add coordx for authentikey (allows for non-ambiguous recovery of pubkey using signature)
        authentikey_public.getW(buffer, (short)(offset+1));
        Util.setShort(buffer, offset, COORD_SIZE);
        offset+=(short)(2+COORD_SIZE);

        initialized_secure_channel= true;

        // return x-coordinate of public key+signature
        // the client can recover full public-key from the signature or
        // by guessing the compression value () and verifying the signature...
        // buffer= [coordx_size(2b) | ephemeralkey_coordx | sig_size(2b) | self_sig | sig2_size | authentikey_sig | coordx_size(2b) | authentikey_coordx]
        return offset;
    }

    /**
     * This function allows to decrypt a secure channel message
     * Note: given the buffer size limitations, the max size for a plaintext command apdu is 154 bytes.
     *
     *  ins: 0x82
     *
     *  p1: 0x00 (RFU)
     *  p2: 0x00 (RFU)
     *  data: [IV(16b) | data_size(2b) | encrypted_command | mac_size(2b) | mac]
     *
     *  return: [decrypted command] in buffer, and the decrypted size. The decrypted command is
     *          guaranteed to hold a complete header [CLA | INS | P1 | P2 | Lc] and Lc data bytes,
     *          so that handlers can trust buffer[OFFSET_LC] (the CLA is checked by the applet).
     *
     */
    short unwrap(byte[] buffer){

        short bytesLeft = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
        short offset = ISO7816.OFFSET_CDATA;

        if (!initialized_secure_channel){
            ISOException.throwIt(SW_SECURE_CHANNEL_UNINITIALIZED);
        }

        // check hmac
        if (bytesLeft<18)
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        short sizein = Util.getShort(buffer, (short) (offset+SIZE_SC_IV));
        // the ciphertext is AES-CBC without padding removal: a whole number of blocks
        if (sizein < 0 || (sizein % SIZE_SC_IV) != 0)
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        if (bytesLeft<(short)(SIZE_SC_IV+2+sizein+2))
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        short sizemac= Util.getShort(buffer, (short) (offset+SIZE_SC_IV+2+sizein));
        if (sizemac != (short)20)
            ISOException.throwIt(SW_SECURE_CHANNEL_WRONG_MAC);
        if (bytesLeft<(short)(SIZE_SC_IV+2+sizein+2+sizemac))
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        // we compute the hmac on the very end of the recvBuffer, so that first bytes can be used as temporary storage between 2 commands.
        HmacSha160.computeHmacSha160(sc_buffer, OFFSET_SC_MACKEY, SIZE_SC_MACKEY, buffer, offset, (short)(SIZE_SC_IV+2+sizein), recvBuffer, (short)248);
        if ( !Satochip.arrayCompareConstantTime(recvBuffer, (short)248, buffer, (short)(offset+SIZE_SC_IV+2+sizein+2), (short)20) )
            ISOException.throwIt(SW_SECURE_CHANNEL_WRONG_MAC);

        // process IV
        // IV received from client should be odd and strictly greater than locally saved IV
        // IV should be random (the 12 first bytes), never reused (the last 4 bytes counter) and different for send and receive
        if ((buffer[(short)(offset+SIZE_SC_IV-(short)1)] & (byte)0x01)==0x00)// should be odd
            ISOException.throwIt(SW_SECURE_CHANNEL_WRONG_IV);
        if ( !Biginteger.lessThan(sc_buffer, OFFSET_SC_IV_COUNTER, buffer, (short)(offset+SIZE_SC_IV_RANDOM), SIZE_SC_IV_COUNTER ) ) //and greater than local IV
            ISOException.throwIt(SW_SECURE_CHANNEL_WRONG_IV);
        // update local IV: local counter = received counter + 1. The next command must use a counter
        // strictly greater, so no value at or below this one is ever accepted again. The +1 also
        // makes the response IV counter even (requests use odd ones), so that request and response
        // IVs never collide under the same session key: do not set local = received.
        Util.arrayCopy(buffer, (short)(offset+SIZE_SC_IV_RANDOM), sc_buffer, OFFSET_SC_IV_COUNTER, SIZE_SC_IV_COUNTER);
        if (Biginteger.add1_carry(sc_buffer, OFFSET_SC_IV_COUNTER, SIZE_SC_IV_COUNTER)){
            // the counter wrapped to 0, which would make old counters acceptable again:
            // the session is exhausted, a new one must be initiated
            initialized_secure_channel = false;
            ISOException.throwIt(SW_SECURE_CHANNEL_WRONG_IV);
        }
        randomData.generateData(sc_buffer, OFFSET_SC_IV_RANDOM, SIZE_SC_IV_RANDOM);
        sc_aes128_cbc.init(sc_sessionkey, Cipher.MODE_DECRYPT, buffer, offset, SIZE_SC_IV);
        offset+=SIZE_SC_IV;
        bytesLeft-=SIZE_SC_IV;

        //decrypt command
        offset+=2;
        bytesLeft-=2;
        if (bytesLeft<sizein)
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        short sizeout=sc_aes128_cbc.doFinal(buffer, offset, sizein, buffer, (short) (0));

        // validate the decrypted command: [CLA | INS | P1 | P2 | Lc | data(Lc) | padding]
        // Lc must not exceed the decrypted data, otherwise the handlers would read stale buffer
        // content. The padding added by the client is not removed (the cipher is NOPAD), so
        // sizeout may exceed 5+Lc: only check the bound.
        if (sizeout < (short)ISO7816.OFFSET_CDATA)
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        if ((short)(ISO7816.OFFSET_CDATA + Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC])) > sizeout)
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        return sizeout;
    }

    /**
     * Encrypts a response through the secure channel, in place.
     * The plaintext (sizeout bytes at buffer[0]) is padded with PKCS#7 and encrypted with
     * the IV generated by the last unwrap().
     *
     * return: [IV(16b) | data_size(2b) | encrypted_response] in buffer, and its size
     */
    short wrap(byte[] buffer, short sizeout){
        // handlers are expected to bound their response; this is a last line of defense
        if (sizeout > MAX_WRAP_SIZE)
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        // buffer contains the data (sizeout)
        // for encryption, data is padded with PKCS#7
        short blocksize=(short)16;
        short padsize= (short) (blocksize - (sizeout%blocksize));

        Util.arrayCopy(buffer, (short)0, tmpBuffer, (short)0, sizeout);
        Util.arrayFillNonAtomic(tmpBuffer, sizeout, padsize, (byte)padsize);//padding
        Util.arrayCopy(sc_buffer, OFFSET_SC_IV, buffer, (short)0, SIZE_SC_IV);
        sc_aes128_cbc.init(sc_sessionkey, Cipher.MODE_ENCRYPT, sc_buffer, OFFSET_SC_IV, SIZE_SC_IV);
        short sizeoutCrypt=sc_aes128_cbc.doFinal(tmpBuffer, (short)0, (short)(sizeout+padsize), buffer, (short) (18));
        Util.setShort(buffer, (short)16, sizeoutCrypt);
        return (short)(18+sizeoutCrypt);
    }
}
