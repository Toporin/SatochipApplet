// Based on the OV-chip 2.0 project
// 
// Digital Security (DS) group at Radboud Universiteit Nijmegen
// Copyright (C) 2008, 2009
// 
// Changes by Toporin for the Bitcoin SatoChip Hardware Wallet
// Sources available on https://github.com/Toporin
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License as
// published by the Free Software Foundation; either version 2 of
// the License, or (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// General Public License in file COPYING in this or one of the
// parent directories for more details.
//

package org.satochip.applet;

import javacard.framework.Util;

public class Biginteger {

	// used for +-< operations on byte arrays
	private static final short digit_mask = 0xff;
	private static final short digit_len = 8;
	
	/**
     * Addition with carry report. Adds other to this number. If this
     * is too small for the result (i.e., an overflow occurs) the
     * method returns true. Further, the result in {@code this} will
     * then be the correct result of an addition modulo the first
     * number that does not fit into {@code this} ({@code 2^(}{@link
     * #digit_len}{@code * }{@link #size this.size}{@code )}), i.e.,
     * only one leading 1 bit is missing. If there is no overflow the
     * method will return false.
     * <P>
     * 
     * compute x= x+y
     * operands are stored Most Signifiant Byte First
     * size is the size in bytes of the operands (should be same size, padded with 0..0 if needed)
     * @param other 
     */
	public static boolean add_carry(byte[] x, short offsetx, byte[] y, short offsety, short size)
    {
        short akku = 0;
        short j = (short)(offsetx+size-1); 
        for(short i = (short)(offsety+size-1); i >= offsety; i--, j--) {
            akku = (short)(akku + (x[j] & digit_mask) + (y[i] & digit_mask));

            x[j] = (byte)(akku & digit_mask);
            akku = (short)((akku >>> digit_len) & digit_mask);
        }
        
        return akku != 0;
    }
	
	/**
	 * compute x= x+1
	 * operands are stored Most Signifiant Byte First
	 * size is the size in bytes of the operand x
	 */
	public static boolean add1_carry(byte[] x, short offsetx, short size)
    {
		//short digit_mask = (short)0xff;
		//short digit_len = 8;
		short akku = 1; // first carry set to 1 for increment
        for(short i = (short)(offsetx+size-1); i >= offsetx; i--) {
            akku = (short) ((x[i] & digit_mask) + akku);

            x[i] = (byte)(akku & digit_mask);
            akku = (short)((akku >>> digit_len) & digit_mask);
        }
        
        return akku != 0;
    }
	
	/**
     * 
     * Subtraction. Subtract {@code other} from {@code this} and store
     * the result in {@code this}. If an overflow occurs the return
     * value is true and the value of this is the correct negative
     * result in two's complement. If there is no overflow the return
     * value is false.
     * <P>
     *
     * compute x= x-y
     * operands are stored Most Signifiant Byte First
     * size is the size in bytes of the operands (should be same size, padded with 0..0 if needed) 
     */
    public static boolean subtract(byte[] x, short offsetx, byte[] y, short offsety, short size) {
        
    	short subtraction_result = 0;
        short carry = 0;

        short i = (short)(offsetx+size-1);
        short j = (short)(offsety+size-1);
        for(; i >= offsetx && j >= offsety; i--, j--) {
            subtraction_result = (short) ((x[i] & digit_mask) - (y[j] & digit_mask) - carry);
            x[i] = (byte)(subtraction_result & digit_mask);
            carry = (short)(subtraction_result < 0 ? 1 : 0);
        }

        return carry > 0;
    }
    
    /**
	 * compute x= x-1
	 * operands are stored Most Signifiant Byte First
	 * size is the size in bytes of the operand x
	 */
	public static boolean subtract1_carry(byte[] x, short offsetx, short size) {
        
    	short subtraction_result = 0;
        short carry = 1;  // first carry set to 1 for decrement

        short i = (short)(offsetx+size-1);
        for(; i >= offsetx; i--) {
            subtraction_result = (short) ((x[i] & digit_mask) - carry);
            x[i] = (byte)(subtraction_result & digit_mask);
            carry = (short)(subtraction_result < 0 ? 1 : 0);
        }

        return carry > 0;
    }
    
    /**
     * Check whether (unsigned)x is strictly smaller than (unsigned)y 
     * operands are stored Most Significant Byte First
     * size is the size in bytes of the operands (should be same size, padded with 0..0 if needed) 
     * returns true if x is strictly smaller than y, false otherwise
     */
    public static boolean lessThan(byte[] x, short offsetx, byte[] y, short offsety, short size) {
        
    	short xs, ys;
        for(short i = offsetx, j=offsety; i < (short)(offsetx+size); i++, j++) {
            xs= (short)(x[i] & digit_mask);
            ys= (short)(y[j] & digit_mask);
        	
        	if(xs < ys) return true;
            if(xs > ys) return false;
        }
        return false; // in case of equality
    }
    
    /**
     * Compare unsigned byte/short in java
     * http://www.javamex.com/java_equivalents/unsigned_arithmetic.shtml 
     */
    public static boolean isStrictlyLessThanUnsigned(byte n1, byte n2) {
    	return (n1 < n2) ^ ((n1 < 0) != (n2 < 0));
	}
    public static boolean isStrictlyLessThanUnsigned(short n1, short n2) {
    	return (n1 < n2) ^ ((n1 < 0) != (n2 < 0));
	}
    
    /**
    * Check whether x is strictly equal to 0 
    * operands are stored Most Signifiant Byte First (big-endian)
    * size is the size in bytes of the operand 
    * returns true if x is equal to 0, false otherwise
    */
    public static boolean equalZero(byte[] x, short offsetx, short size) {
        
        for(short i = offsetx; i < (short)(offsetx+size); i++) {
            if(x[i] != 0) return false;
        }
        return true;
    }
    
    public static void Shift1bit(byte[] src, short srcOffset, short size){
		short rightShifts=(short)1;
		short leftShifts = (short)7;
		short mask= 0x00FF;
		 
		byte previousByte = src[srcOffset]; // keep the byte before modification
		src[srcOffset]= (byte) (((src[srcOffset]&mask)>>rightShifts)&mask);
		for(short i = (short)(srcOffset+1); i < (short)(srcOffset+size); i++) {
			byte tmp = src[i];
			src[i]= (byte) ( (((src[i]&mask)>>rightShifts)&mask) | ((previousByte&mask)<<leftShifts) );
			previousByte= tmp;
		}    
    }
    
    /**
     * For a Biginteger bi of given size stored in a given byte array at given offset, 
     * the function sets the Biginteger to zero*/
    public static void setZero(byte[] x, short offsetx, short size) {
    	Util.arrayFillNonAtomic(x, offsetx, (short)size, (byte)0x00);
    }
    
    /**
     * For a Biginteger bi of given size stored in a given byte array at given offset, 
     * the function sets the Biginteger LSB to value*/
    public static void setByte(byte[] x, short offsetx, short size, byte value) {
    	setZero(x, offsetx, size);
    	x[(short)(offsetx+size-1)] = value;	
    }
    
    /**
     * For a Biginteger bi of given size stored in a given byte array at given offset, 
     * the function returns the least significant byte lsb if (bi==lsb) or Ox00ff otherwise*/
    public static short getLSB(byte[] x, short offsetx, short size) {
        for (short i= offsetx; i<(short)(offsetx+size-1); i++){
    		if (x[i]!=0)
    			return (short)0xff;
    	}
        return (short)(x[(short)(offsetx+size-1)] & digit_mask);
    }
    
    /**
     * This function swaps the bytes of Biginteger in x to Biginteger in y*/
    public static void swap(byte[] x, short offsetx, byte[] y, short offsety, short size) {
        for (short i= 0; i<size; i++){
        	y[(short)(offsety+size-i-1)]=x[(short)(offsetx+i)];
    	}
    }
    
    // VarInt
    /* Encode a short into Bitcoin's VarInt format and return number of byte set */
    public static short encodeShortToVarInt(short value, byte[] buffer, short offset) {
        
    	//if (value<((short)253)) { // signed comparison!!
        if (Biginteger.isStrictlyLessThanUnsigned(value,(short)253)){
    		buffer[offset]=(byte)(value & 0xFF);
            return (short)1;
        } else {
        	buffer[offset++]= (byte)253;
        	buffer[offset++]= (byte)(value & 0xff);
        	buffer[offset++]= (byte)(value>>>8);
        	return (short)3; 
        } 
    }
    
    /* Encode a 4-byte int into Bitcoin's VarInt format and return number of byte set */
    public static short encodeVarInt(byte[] src, short src_offset, byte[] dst, short dst_offset) {
        if (src[src_offset]!=0 | 
        	src[(short)(src_offset+1)]!=0){ // 4-bytes integer
        	dst[dst_offset]= (byte)0xfe;
        	dst[(short)(dst_offset+1)]= src[(short)(src_offset+3)]; // little endian
        	dst[(short)(dst_offset+2)]= src[(short)(src_offset+2)]; 
        	dst[(short)(dst_offset+3)]= src[(short)(src_offset+1)]; 
        	dst[(short)(dst_offset+4)]= src[src_offset]; 
        	return (short)5;
        }
        else if (src[(short)(src_offset+2)]!=0 | 
        		 (src[(short)(src_offset+3)] & 0xff)>=0xfd){ // short integer
        	dst[dst_offset]= (byte)0xfd;
        	dst[(short)(dst_offset+1)]= src[(short)(src_offset+3)]; // little endian
        	dst[(short)(dst_offset+2)]= src[(short)(src_offset+2)]; 
        	return (short)3;
        }
        else{
        	dst[dst_offset]=src[(short)(src_offset+3)];
            return (short)1;
        }
    }
}
