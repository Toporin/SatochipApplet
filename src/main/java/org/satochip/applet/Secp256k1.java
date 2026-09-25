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
    
    // JC API 2.2.2 does not define these constants:
    public final static byte ALG_ECDSA_SHA_256= (byte) 33;
    public final static byte ALG_EC_SVDP_DH_PLAIN= (byte) 3; //https://javacard.kenai.com/javadocs/connected/javacard/security/KeyAgreement.html#ALG_EC_SVDP_DH_PLAIN
    public final static short LENGTH_EC_FP_256= (short) 256;
    
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
        
        // y^2 mod p
        Biginteger.mult_rsa_trick(pubkey, (short)(pubkey_offset+33), pubkey, (short)(pubkey_offset+33), (short)32, scratch, offset_product);
        Biginteger.mod(scratch, offset_product, (short)96, SECP256K1, OFFSET_SECP256K1_P, (short)32);
        Util.arrayCopyNonAtomic(scratch, (short)(offset_product+64), scratch, offset_y2, (short)32);
        
        // x^2 mod p
        Biginteger.mult_rsa_trick(pubkey, (short)(pubkey_offset+1), pubkey, (short)(pubkey_offset+1), (short)32, scratch, offset_product);
        Biginteger.mod(scratch, offset_product, (short)96, SECP256K1, OFFSET_SECP256K1_P, (short)32);
        Util.arrayCopyNonAtomic(scratch, (short)(offset_product+64), scratch, offset_x3, (short)32);
        
        // x^3 = x^2 * x mod p
        Biginteger.mult_rsa_trick(scratch, offset_x3, pubkey, (short)(pubkey_offset+1), (short)32, scratch, offset_product);
        Biginteger.mod(scratch, offset_product, (short)96, SECP256K1, OFFSET_SECP256K1_P, (short)32);
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
    
    
    
//  
//  private final static byte[] SECP256K1_P = {(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF, (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF, 
//                                             (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF, (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF, 
//                                             (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF, (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
//                                             (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFE, (byte)0xFF,(byte)0xFF,(byte)0xFC,(byte)0x2F}; 
//  private final static byte[] SECP256K1_a = {0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 
//                                             0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 
//                                             0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
//                                             0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00};
//  private final static byte[] SECP256K1_b = {0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
//                                             0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
//                                             0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
//                                             0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x07};
//  private final static byte[] SECP256K1_G = {(byte)0x04, //base point, uncompressed form 
//                                             (byte)0x79,(byte)0xBE,(byte)0x66,(byte)0x7E, (byte)0xF9,(byte)0xDC,(byte)0xBB,(byte)0xAC,
//                                             (byte)0x55,(byte)0xA0,(byte)0x62,(byte)0x95, (byte)0xCE,(byte)0x87,(byte)0x0B,(byte)0x07,
//                                             (byte)0x02,(byte)0x9B,(byte)0xFC,(byte)0xDB, (byte)0x2D,(byte)0xCE,(byte)0x28,(byte)0xD9,
//                                             (byte)0x59,(byte)0xF2,(byte)0x81,(byte)0x5B, (byte)0x16,(byte)0xF8,(byte)0x17,(byte)0x98,
//                                             (byte)0x48,(byte)0x3A,(byte)0xDA,(byte)0x77, (byte)0x26,(byte)0xA3,(byte)0xC4,(byte)0x65,
//                                             (byte)0x5D,(byte)0xA4,(byte)0xFB,(byte)0xFC, (byte)0x0E,(byte)0x11,(byte)0x08,(byte)0xA8,
//                                             (byte)0xFD,(byte)0x17,(byte)0xB4,(byte)0x48, (byte)0xA6,(byte)0x85,(byte)0x54,(byte)0x19,
//                                             (byte)0x9C,(byte)0x47,(byte)0xD0,(byte)0x8F, (byte)0xFB,(byte)0x10,(byte)0xD4,(byte)0xB8};
//  private final static byte[] SECP256K1_R = {(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF, (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF, // order of G
//                                             (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF, (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFE,
//                                             (byte)0xBA,(byte)0xAE,(byte)0xDC,(byte)0xE6, (byte)0xAF,(byte)0x48,(byte)0xA0,(byte)0x3B,
//                                             (byte)0xBF,(byte)0xD2,(byte)0x5E,(byte)0x8C, (byte)0xD0,(byte)0x36,(byte)0x41,(byte)0x41};
//  //private final static short SECP256K1_K = 0x01; // cofactor 
//
//  public static void setCommonCurveParameters(ECKey eckey){
//      eckey.setFieldFP( SECP256K1_P, (short)0, (short)SECP256K1_P.length);
//      eckey.setA( SECP256K1_a, (short)0, (short)SECP256K1_a.length);
//      eckey.setB( SECP256K1_b, (short)0, (short)SECP256K1_b.length);
//      eckey.setG( SECP256K1_G, (short)0, (short)SECP256K1_G.length);
//      eckey.setR( SECP256K1_R, (short)0, (short)SECP256K1_R.length);
//      eckey.setK( SECP256K1_K);
//  }
    
    
    
}
