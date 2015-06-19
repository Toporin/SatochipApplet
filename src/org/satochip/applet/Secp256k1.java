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
	
	
	
//	
//	private final static byte[] SECP256K1_P = {(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF, (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF, 
//											   (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF, (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF, 
//											   (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF, (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
//											   (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFE, (byte)0xFF,(byte)0xFF,(byte)0xFC,(byte)0x2F}; 
//	private final static byte[] SECP256K1_a = {0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 
//											   0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 
//											   0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
//											   0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00};
//	private final static byte[] SECP256K1_b = {0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
//											   0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
//											   0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
//											   0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x07};
//	private final static byte[] SECP256K1_G = {(byte)0x04, //base point, uncompressed form 
//											   (byte)0x79,(byte)0xBE,(byte)0x66,(byte)0x7E, (byte)0xF9,(byte)0xDC,(byte)0xBB,(byte)0xAC,
//											   (byte)0x55,(byte)0xA0,(byte)0x62,(byte)0x95, (byte)0xCE,(byte)0x87,(byte)0x0B,(byte)0x07,
//											   (byte)0x02,(byte)0x9B,(byte)0xFC,(byte)0xDB, (byte)0x2D,(byte)0xCE,(byte)0x28,(byte)0xD9,
//											   (byte)0x59,(byte)0xF2,(byte)0x81,(byte)0x5B, (byte)0x16,(byte)0xF8,(byte)0x17,(byte)0x98,
//											   (byte)0x48,(byte)0x3A,(byte)0xDA,(byte)0x77, (byte)0x26,(byte)0xA3,(byte)0xC4,(byte)0x65,
//											   (byte)0x5D,(byte)0xA4,(byte)0xFB,(byte)0xFC, (byte)0x0E,(byte)0x11,(byte)0x08,(byte)0xA8,
//											   (byte)0xFD,(byte)0x17,(byte)0xB4,(byte)0x48, (byte)0xA6,(byte)0x85,(byte)0x54,(byte)0x19,
//											   (byte)0x9C,(byte)0x47,(byte)0xD0,(byte)0x8F, (byte)0xFB,(byte)0x10,(byte)0xD4,(byte)0xB8};
//	private final static byte[] SECP256K1_R = {(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF, (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF, // order of G
//											   (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF, (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFE,
//											   (byte)0xBA,(byte)0xAE,(byte)0xDC,(byte)0xE6, (byte)0xAF,(byte)0x48,(byte)0xA0,(byte)0x3B,
//											   (byte)0xBF,(byte)0xD2,(byte)0x5E,(byte)0x8C, (byte)0xD0,(byte)0x36,(byte)0x41,(byte)0x41};
//	//private final static short SECP256K1_K = 0x01; // cofactor 
//
//	public static void setCommonCurveParameters(ECKey eckey){
//		eckey.setFieldFP( SECP256K1_P, (short)0, (short)SECP256K1_P.length);
//		eckey.setA( SECP256K1_a, (short)0, (short)SECP256K1_a.length);
//		eckey.setB( SECP256K1_b, (short)0, (short)SECP256K1_b.length);
//		eckey.setG( SECP256K1_G, (short)0, (short)SECP256K1_G.length);
//		eckey.setR( SECP256K1_R, (short)0, (short)SECP256K1_R.length);
//		eckey.setK( SECP256K1_K);
//	}
	
	
	
}
