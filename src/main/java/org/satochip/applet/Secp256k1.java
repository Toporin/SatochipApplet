/*
 * SatoChip Bitcoin Hardware Wallet based on javacard
 * (c) 2015 by Toporin - 16DMCk4WUaHofchAhpMaQS4UPm4urcy2dN
 * Sources available on https://github.com/Toporin  
 *               
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *   
 */ 
package org.satochip.applet;

import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.security.ECKey;
import javacard.security.ECPrivateKey;

public class Secp256k1 {
    
    //Bitcoin: default parameters for EC curve secp256k1
    public final static byte[] SECP256K1 = {
            // P - offset 0
           (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF, (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF, 
           (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF, (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF, 
           (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF, (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
           (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFE, (byte)0xFF,(byte)0xFF,(byte)0xFC,(byte)0x2F, 
           // a - offset 32
           0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 
           0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 
           0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
           0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
           // b  - offset 64
           0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
           0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
           0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
           0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x07,
           //R - offset 96
           (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF, (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF, // order of G
           (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF, (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFE,
           (byte)0xBA,(byte)0xAE,(byte)0xDC,(byte)0xE6, (byte)0xAF,(byte)0x48,(byte)0xA0,(byte)0x3B,
           (byte)0xBF,(byte)0xD2,(byte)0x5E,(byte)0x8C, (byte)0xD0,(byte)0x36,(byte)0x41,(byte)0x41,
           //G - offset 128
           (byte)0x04, //base point, uncompressed form 
           (byte)0x79,(byte)0xBE,(byte)0x66,(byte)0x7E, (byte)0xF9,(byte)0xDC,(byte)0xBB,(byte)0xAC,
           (byte)0x55,(byte)0xA0,(byte)0x62,(byte)0x95, (byte)0xCE,(byte)0x87,(byte)0x0B,(byte)0x07,
           (byte)0x02,(byte)0x9B,(byte)0xFC,(byte)0xDB, (byte)0x2D,(byte)0xCE,(byte)0x28,(byte)0xD9,
           (byte)0x59,(byte)0xF2,(byte)0x81,(byte)0x5B, (byte)0x16,(byte)0xF8,(byte)0x17,(byte)0x98,
           (byte)0x48,(byte)0x3A,(byte)0xDA,(byte)0x77, (byte)0x26,(byte)0xA3,(byte)0xC4,(byte)0x65,
           (byte)0x5D,(byte)0xA4,(byte)0xFB,(byte)0xFC, (byte)0x0E,(byte)0x11,(byte)0x08,(byte)0xA8,
           (byte)0xFD,(byte)0x17,(byte)0xB4,(byte)0x48, (byte)0xA6,(byte)0x85,(byte)0x54,(byte)0x19,
           (byte)0x9C,(byte)0x47,(byte)0xD0,(byte)0x8F, (byte)0xFB,(byte)0x10,(byte)0xD4,(byte)0xB8    
    };
    
    public final static short SECP256K1_K = 0x01; // cofactor 
    public final static short OFFSET_SECP256K1_P = 0;
    public final static short OFFSET_SECP256K1_a = 32;
    public final static short OFFSET_SECP256K1_b = 64;
    public final static short OFFSET_SECP256K1_R = 96;
    public final static short OFFSET_SECP256K1_G = 128;
    
    public static void setCommonCurveParameters(ECKey eckey){
        eckey.setFieldFP( SECP256K1, OFFSET_SECP256K1_P, (short)32);
        eckey.setA( SECP256K1, OFFSET_SECP256K1_a, (short)32);
        eckey.setB( SECP256K1, OFFSET_SECP256K1_b, (short)32);
        eckey.setR( SECP256K1, OFFSET_SECP256K1_R, (short)32);
        eckey.setG( SECP256K1, OFFSET_SECP256K1_G, (short)65);
        eckey.setK( SECP256K1_K);
    }
    
    public static boolean checkCurveParameters(ECKey eckey, byte[] tmpbuffer, short tmpoffset){
        
        eckey.getA(tmpbuffer, tmpoffset);
        if (0!=Util.arrayCompare(tmpbuffer, tmpoffset, SECP256K1, OFFSET_SECP256K1_a, (short)32))
            return false;
        eckey.getB(tmpbuffer, tmpoffset);
        if (0!=Util.arrayCompare(tmpbuffer, tmpoffset, SECP256K1, OFFSET_SECP256K1_b, (short)32))
            return false;
        eckey.getG(tmpbuffer, tmpoffset);
        if (0!=Util.arrayCompare(tmpbuffer, tmpoffset, SECP256K1, OFFSET_SECP256K1_G, (short)65))
            return false;
        eckey.getR(tmpbuffer, tmpoffset);
        if (0!=Util.arrayCompare(tmpbuffer, tmpoffset, SECP256K1, OFFSET_SECP256K1_R, (short)32))
            return false;
        eckey.getField(tmpbuffer, tmpoffset);
        if (0!=Util.arrayCompare(tmpbuffer, tmpoffset, SECP256K1, OFFSET_SECP256K1_P, (short)32))
            return false;
        if (eckey.getK()!= SECP256K1_K)
            return false;
        
        return true;
    }
    
    /**
     * Checks that a 65-byte uncompressed EC point (0x04 | X(32b) | Y(32b)) is a valid
     * point on the secp256k1 curve: X and Y must be canonical field elements
     * (strictly smaller than p) and must satisfy Y^2 = X^3 + 7 (mod p).
     *
     * This check must be performed on any externally-provided point before it is used
     * in an EC operation (e.g. ECDH), to mitigate invalid-curve attacks (Lim-Lee small
     * subgroup attacks) against the card's private keys.
     * Since secp256k1 has cofactor 1, any point on the curve (except the point at
     * infinity, which has no affine representation) has full order n, so checking the
     * curve equation is sufficient.
     *
     * @param pubkey         buffer containing the 65-byte uncompressed point
     * @param pubkey_offset  offset of the point in pubkey
     * @param scratch        scratch buffer (192 bytes from scratch_offset), clobbered during the check
     * @param scratch_offset offset of the scratch area in scratch
     * @return true if the point is on secp256k1, false otherwise
     */
    public static boolean isOnCurve(byte[] pubkey, short pubkey_offset, byte[] scratch, short scratch_offset){
        // scratch layout: [0..96): mult/mod scratch | [96..128): y^2 mod p | [128..160): (x^3+7) mod p | [160..192): constant 7
        short offset_product = scratch_offset;
        short offset_y2 = (short)(scratch_offset+96);
        short offset_x3 = (short)(scratch_offset+128);
        short offset_cst7 = (short)(scratch_offset+160);
        
        // X and Y must be canonical field elements
        if (!Biginteger.lessThan(pubkey, (short)(pubkey_offset+1), SECP256K1, OFFSET_SECP256K1_P, (short)32))
            return false;
        if (!Biginteger.lessThan(pubkey, (short)(pubkey_offset+33), SECP256K1, OFFSET_SECP256K1_P, (short)32))
            return false;
        
        if (!Biginteger.FLAG_FAST_MULT_VIA_RSA){
            // The RSA engine used by mult_rsa_trick() is not available on this card:
            // the curve equation cannot be verified, so the point is accepted with only
            // the canonical-encoding checks above (same behavior as before this check).
            return true;
        }
        
        // the products below are 96-byte buffers whose 32 leading bytes are zero (both factors are
        // < p < 2^256): reduceModP() works on the 64 trailing bytes, the result is in the last 32
        short offset_product_low = (short)(offset_product+32);

        // y^2 mod p
        Biginteger.square_rsa(pubkey, (short)(pubkey_offset+33), (short)32, scratch, offset_product);
        reduceModP(scratch, offset_product_low);
        Util.arrayCopyNonAtomic(scratch, (short)(offset_product+64), scratch, offset_y2, (short)32);

        // x^2 mod p
        Biginteger.square_rsa(pubkey, (short)(pubkey_offset+1), (short)32, scratch, offset_product);
        reduceModP(scratch, offset_product_low);
        Util.arrayCopyNonAtomic(scratch, (short)(offset_product+64), scratch, offset_x3, (short)32);

        // x^3 = x^2 * x mod p
        Biginteger.mult_rsa_trick(scratch, offset_x3, pubkey, (short)(pubkey_offset+1), (short)32, scratch, offset_product);
        reduceModP(scratch, offset_product_low);
        Util.arrayCopyNonAtomic(scratch, (short)(offset_product+64), scratch, offset_x3, (short)32);
        
        // x^3 + 7 mod p (no carry possible: (x^3 mod p) + 7 <= (p-1)+7 < 2^256)
        Util.arrayFillNonAtomic(scratch, offset_cst7, (short)32, (byte)0);
        scratch[(short)(offset_cst7+31)] = (byte)0x07;
        Biginteger.add_carry(scratch, offset_x3, scratch, offset_cst7, (short)32);
        if (!Biginteger.lessThan(scratch, offset_x3, SECP256K1, OFFSET_SECP256K1_P, (short)32)){
            Biginteger.subtract(scratch, offset_x3, SECP256K1, OFFSET_SECP256K1_P, (short)32);
        }
        
        // check y^2 == (x^3 + 7) (mod p)
        boolean is_on_curve = (Util.arrayCompare(scratch, offset_y2, scratch, offset_x3, (short)32) == (byte)0);
        // clear scratch
        Util.arrayFillNonAtomic(scratch, scratch_offset, (short)192, (byte)0);
        return is_on_curve;
    }

    /**
     * Reduces a 64-byte number modulo the secp256k1 field prime p, in place.
     *
     * p = 2^256 - c with c = 2^32 + 977 = 0x1000003D1, so H*2^256 + L == H*c + L (mod p). Each fold
     * replaces [H | L] by H*c + L, which is linear in the size, unlike the schoolbook division of
     * Biginteger.mod(). From any 64-byte input, H*c + L < 2^290 (37 bytes); a second fold leaves
     * H <= 1, and then L < 2^67, so a third fold ends with H = 0. A final subtraction brings
     * L < 2^256 < 2p below p.
     *
     * NOT constant time (the number of folds and the final subtraction depend on the value):
     * for public operands only, such as the coordinates checked by isOnCurve().
     *
     * @param x      buffer holding [H(32b) | L(32b)], big-endian
     * @param offset offset of H in x
     *               on return, x[offset..offset+32) is zero and x[offset+32..offset+64) holds x mod p
     */
    static void reduceModP(byte[] x, short offset) {
        short offset_low = (short)(offset+32);
        while (!Biginteger.equalZero(x, offset, (short)32)) {
            // one pass over the columns of H*c + L, least significant byte first. Column m (byte m
            // counted from the least significant one) adds l_m + h_m*0xD1 + h_(m-1)*0x03 + h_(m-4).
            // Each column fits in an unsigned 16-bit accumulator: at most 255*(1+209+3+1) + carry,
            // with carry <= 215, i.e. < 55100 < 2^16. The short arithmetic wraps modulo 2^16, so
            // the low byte and (acc >> 8) & 0xFF are exact even when acc reads as negative.
            // The result is written in place: column m overwrites l_m (m < 32), only read at
            // column m, or h_(m-32) (m >= 32), whose last use is at column m-28.
            short carry = (short)0;
            for (short m = (short)0; m < (short)37; m++) {
                short acc = carry;
                if (m < (short)32) {
                    acc += (short)(x[(short)(offset_low+31-m)] & 0xFF);
                    acc += (short)((short)(x[(short)(offset+31-m)] & 0xFF) * (short)0xD1);
                }
                if (m >= (short)1 && m <= (short)32) {
                    acc += (short)((short)(x[(short)(offset+32-m)] & 0xFF) * (short)0x03);
                }
                if (m >= (short)4 && m <= (short)35) {
                    acc += (short)(x[(short)(offset+35-m)] & 0xFF);
                }
                if (m < (short)32) {
                    x[(short)(offset_low+31-m)] = (byte)acc;
                } else {
                    x[(short)(offset+63-m)] = (byte)acc;
                }
                carry = (short)((short)(acc >> 8) & 0xFF);
            }
            // the result holds in 37 bytes (carry is 0 here): H is now its 5 high bytes, the other
            // bytes of H still hold their old value and must be cleared
            Util.arrayFillNonAtomic(x, offset, (short)27, (byte)0);
        }
        // L < 2^256 < 2p: at most one subtraction
        if (!Biginteger.lessThan(x, offset_low, SECP256K1, OFFSET_SECP256K1_P, (short)32)) {
            Biginteger.subtract(x, offset_low, SECP256K1, OFFSET_SECP256K1_P, (short)32);
        }
    }
}
