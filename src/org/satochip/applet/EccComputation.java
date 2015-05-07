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

import javacard.framework.Util;
import javacard.security.KeyBuilder;
import javacard.security.RSAPublicKey;
import javacard.security.RandomData;
import javacardx.crypto.Cipher;

public class EccComputation {
	
	private static final short EXP2=0;
	private static final short EXP3=1;
	private static final short EXP4=2;
	private static final short EXP6=3;
	private static final short EXP8=4;
	private static final short EXP12=5;
	private static final short EXP16=6;
	private static final short EXP24=7;
	private static final short EXP32=8;
	private static final short EXP48=9;
	private static final short EXP96=10;
	private static final short DECR=11;

	// Q decomposition: divide by a factor of 96 (2^5*3) or decrement then repeat
	private final static byte[] QDECOMP={
		EXP4, DECR, EXP2, DECR, EXP32, DECR, EXP2, DECR,
		EXP2, DECR, EXP2, DECR, EXP2, DECR, EXP2, DECR, 
		EXP2, DECR, EXP2, DECR, EXP2, DECR, EXP2, DECR, 
		EXP2, DECR, EXP2, DECR, EXP2, DECR, EXP2, DECR, 
		EXP2, DECR, EXP2, DECR, EXP2, DECR, EXP2, DECR,
		EXP2, DECR, EXP2, DECR, EXP2, DECR, EXP2, DECR, 
		EXP4, DECR, EXP6, EXP3, DECR, EXP6, DECR, EXP96, 
		DECR, EXP6, EXP3, DECR, EXP2, DECR, EXP2, DECR, 
		EXP2, DECR, EXP4, DECR, EXP48, DECR, EXP6, DECR, 
		EXP8, DECR, EXP2, DECR, EXP2, DECR, EXP2, DECR, 
		EXP2, DECR, EXP4, DECR, EXP6, DECR, EXP16, DECR, 
		EXP6, DECR, EXP2, DECR, EXP2, DECR, EXP4, DECR, 
		EXP6, EXP3, EXP3, DECR, EXP24, DECR, EXP2, DECR, 
		EXP4, DECR, EXP6, EXP3, DECR, EXP6, DECR, EXP16, 
		DECR, EXP48, DECR, EXP6, EXP3, EXP3, DECR, EXP2, 
		DECR, EXP2, DECR, EXP2, DECR, EXP4, DECR, EXP6, 
		EXP3, DECR, EXP6, EXP3, DECR, EXP12, DECR, EXP2, 
		DECR, EXP4, DECR, EXP24, EXP3, DECR, EXP2, DECR, 
		EXP8, DECR, EXP8, DECR, EXP8, DECR, EXP2, DECR, 
		EXP2, DECR, EXP2, DECR, EXP32, EXP8, DECR, EXP6, 
		DECR, EXP96, DECR, EXP12, EXP3, DECR, EXP12, DECR, 
		EXP4, DECR, EXP6, DECR, EXP6, DECR, EXP6, EXP3, 
		EXP3, DECR,	EXP6, DECR, EXP48, DECR, EXP12, EXP3, 
		EXP3, EXP3, DECR, EXP4, DECR, EXP6, EXP3, EXP3, 
		DECR, EXP32, EXP8, DECR, EXP6, DECR, EXP2, DECR, 
		EXP2, DECR, EXP2, DECR, EXP16, DECR, EXP6, DECR, 
		EXP12, DECR, EXP2, DECR, EXP2, DECR, EXP2, DECR, 
		EXP4, DECR, EXP12, DECR
	};
	
	private final static byte[] EXP={
		(byte)2, (byte)3, (byte)4, (byte)6, 
		(byte)8, (byte)12, (byte)16, (byte)24, 
		(byte)32, (byte)48, (byte)96};
	
	private final static short[] EXPOFF={
		(short)48, (short)64, (short)72, (short)80, 
		(short)84, (short)88, (short)90, (short)92, 
		(short)93, (short)94, (short)95};
	
	private final static byte[] SECP256K1_P = 
		  {(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF, (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF, 
		   (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF, (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF, 
		   (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF, (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
		   (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFE, (byte)0xFF,(byte)0xFF,(byte)0xFC,(byte)0x2F}; 
	
	// q= (p+1)/4
//	private final static byte[] Q=
//		{(byte)0x3f,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,
//		 (byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,
//		 (byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,
//		 (byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xbf,(byte)0xff,(byte)0xff,(byte)0x0c};
		
	private static byte[] tmpBuffer;
	private static final short REG0=(short)0;
	private static final short REG1=(short)128;
	private static final short REG2=(short)160;
	private static final short REG3=(short)192;
	private static final short REG4=(short)224;
	//private static final short REG5=(short)256;
	private static final short OPLENGTH=(short)32;
	
	private static RSAPublicKey rsa_PublicKey = null;
	private static Cipher m_encryptCipherRSA = null;
	public static final byte ALG_RSA_NOPAD = 12;
	
	public static void init(byte[] tmp){
		tmpBuffer=tmp;
		
		// Allocate objects if not allocated yet
	    if (rsa_PublicKey == null) { 
	 	   rsa_PublicKey = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC,KeyBuilder.LENGTH_RSA_1024,false); 
	    } 
	    if (m_encryptCipherRSA == null) { 
		   m_encryptCipherRSA = Cipher.getInstance(ALG_RSA_NOPAD, false); 
	    }
	    
	    // set SECP256K1_P*2^96 
        Util.arrayFillNonAtomic(tmpBuffer, REG0, (short)128, (byte)0);
        Util.arrayCopyNonAtomic(SECP256K1_P, (short)0, tmpBuffer, REG0, (short)SECP256K1_P.length);
        rsa_PublicKey.setModulus(tmpBuffer, REG0, (short)128);   
	}
	
	
	// uses REG3 & REG4
	public static void SqrtRootOpt(byte[] src, short srcOff, byte[] dst, short dstOff){ //, short ctrstop){
		// y^2 = z = x^3+7 (mod p)
		// y= sqrt(z)= z^((p+1)/4) (mod p)
		
		// z= x^3+7	    
		ModularExp32b(src, srcOff, tmpBuffer, REG4, EXP3);
		Util.arrayFillNonAtomic(tmpBuffer, REG2, OPLENGTH, (byte)0);
		tmpBuffer[(short)(REG2+31)]=(byte)7; //LSB
		if(Biginteger.add_carry(tmpBuffer, REG4, tmpBuffer, REG2, OPLENGTH)){
			Biginteger.subtract(tmpBuffer, REG4, SECP256K1_P, (short)0, OPLENGTH);
		}
						
		Util.arrayFillNonAtomic(tmpBuffer, REG3, OPLENGTH, (byte)0);
		tmpBuffer[(short)(REG3+31)]=(byte)1; //LSB
		
		for(short i=0; i<QDECOMP.length; i++){
			
			byte op= QDECOMP[i];
			if (op==DECR){
				ModularMult32bOpt(tmpBuffer, REG3, tmpBuffer, REG4, tmpBuffer, REG3);
			}
			else{
				ModularExp32b(tmpBuffer, REG4, tmpBuffer, REG4, op);
			}
			//if (counter==ctrstop) //debug
				//break;
		}
		
		Util.arrayCopyNonAtomic(tmpBuffer, REG3, dst, dstOff, OPLENGTH);
		//Util.arrayCopyNonAtomic(tmpBuffer, REG3, dst, dstOff, (short)96);//debug
	}
	
	// uses REG0
	public static void ModularExp32b(byte[] src, short srcOff, byte[] dst, short dstOff, short exp){
		//https://proofwiki.org/wiki/Congruence_by_Product_of_Modulo
		Util.arrayFillNonAtomic(tmpBuffer, REG0, (short)128, (byte)0);
		Util.arrayCopyNonAtomic(src, srcOff, tmpBuffer, EXPOFF[exp], OPLENGTH);
		
		rsa_PublicKey.setExponent(EXP, (short)exp, (short) 1);
		m_encryptCipherRSA.init(rsa_PublicKey, Cipher.MODE_ENCRYPT);
	    short offset = m_encryptCipherRSA.doFinal(tmpBuffer, (short)0, (short)128, tmpBuffer, (byte) 0);   
	    
	    Util.arrayCopyNonAtomic(tmpBuffer, (short)0, dst, dstOff, OPLENGTH);
	}	
	
	// uses REG1 & REG2
	public static void ModularMult32bOpt(byte[]x, short xOff, byte[] y, short yOff, byte[] dst, short dstOff){
		// https://www.cosic.esat.kuleuven.be/publications/article-1296.pdf
		// 4xy = (x+y)^2 - (x-y)^2 (mod n)
		// (x+y)
		Util.arrayCopyNonAtomic(x, xOff, tmpBuffer, REG1, OPLENGTH);
		if(Biginteger.add_carry(tmpBuffer, REG1, y, yOff, OPLENGTH)){
			Biginteger.subtract(tmpBuffer, REG1, SECP256K1_P, (short)0, OPLENGTH);
		}else{
		    // in the unlikely case where SECP256K1_P<=x+y<2^256
			if(!Biginteger.lessThan(tmpBuffer, REG1, SECP256K1_P, (short)0, OPLENGTH)){	
				Biginteger.subtract(tmpBuffer, REG1, SECP256K1_P, (short)0, OPLENGTH);
			}
		}

		// (x+y)^2
		ModularExp32b(tmpBuffer, REG1, tmpBuffer, REG1, EXP2);
		
		// (x-y)
		Util.arrayCopyNonAtomic(x, xOff, tmpBuffer, REG2, OPLENGTH);
		if(Biginteger.lessThan(tmpBuffer, REG2, y, yOff, OPLENGTH)){
			Biginteger.add_carry(tmpBuffer, REG2, SECP256K1_P, (short)0, OPLENGTH);
		}
		Biginteger.subtract(tmpBuffer, REG2, y, yOff, OPLENGTH);
		
		// (x-y)^2
		ModularExp32b(tmpBuffer, REG2, tmpBuffer, REG2, EXP2);
				
		// (x+y)^2-(x-y)^2
		if(Biginteger.lessThan(tmpBuffer, REG1, tmpBuffer, REG2, OPLENGTH)){
			Biginteger.add_carry(tmpBuffer, REG1, SECP256K1_P, (short)0, OPLENGTH);
		}
		Biginteger.subtract(tmpBuffer, REG1, tmpBuffer, REG2, OPLENGTH);
				
		// divide by 2
		if ((tmpBuffer[(short)(REG1+31)]&1)==0){
			Biginteger.Shift1bit(tmpBuffer, REG1, OPLENGTH);
		}
		else{ // LSB is 1
			boolean carry= Biginteger.add_carry(tmpBuffer, REG1, SECP256K1_P, (short)0, OPLENGTH);
			Biginteger.Shift1bit(tmpBuffer, REG1, OPLENGTH);
			if (carry){// set MSB
				tmpBuffer[REG1]|=(byte)0x80;
			}
		}
		// divide by 2 again
		if ((tmpBuffer[(short)(REG1+31)]&1)==0){
			Biginteger.Shift1bit(tmpBuffer, REG1, OPLENGTH);
		}
		else{ // LSB is 1
			boolean carry= Biginteger.add_carry(tmpBuffer, REG1, SECP256K1_P, (short)0, OPLENGTH);
			Biginteger.Shift1bit(tmpBuffer, REG1, OPLENGTH);
			if (carry){// set MSB
				tmpBuffer[REG1]|=(byte)0x80;
			}
		}
		
		Util.arrayCopyNonAtomic(tmpBuffer, REG1, dst, dstOff, OPLENGTH);
	}
	
	public static void getSecondPoint(byte[]src, short srcOff, byte[] dst, short dstOff){
		Util.arrayCopyNonAtomic(SECP256K1_P, (short)0, dst, dstOff, OPLENGTH);
		Biginteger.subtract(dst, dstOff, src, srcOff, OPLENGTH);		
	}

}

