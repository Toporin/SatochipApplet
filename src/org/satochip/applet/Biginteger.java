// SatoChip Bitcoin Hardware Wallet based on javacard
// (c) 2015-2019 by Toporin
// Sources available on https://github.com/Toporin
//
// Code below is based on the OV-chip 2.0 project
// Digital Security (DS) group at Radboud Universiteit Nijmegen
// Copyright (C) 2008, 2009
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

import javacard.framework.JCSystem;
import javacard.framework.SystemException;
import javacard.framework.Util;
import javacard.security.KeyPair;
import javacard.security.RSAPublicKey;
import javacardx.crypto.Cipher;

public class Biginteger {

    // used for +-< operations on byte arrays
    public static final short digit_mask = 0xff;
    public static final short digit_len = 8;
    /**
     * Size in bits of a double digit. 16 for the short/short configuration, 64
     * for the int/long configuration.
     */
    public static final short double_digit_len = 16;
    
    /**
     * Bitmask for erasing the sign bit in a double digit. short 0x7fff for the
     * short/short configuration, long 0x7fffffffffffffffL for the int/long
     * configuration.
     */
    public static final short positive_double_digit_mask = 0x7fff;
    
    // tmp array
    // warning: buffers should be same size to facilitate computations
    public static final short BUFFER_SIZE = (short)96;//65 is not OK => FLAG_FAST_MULT_VIA_RSA is false; // TODO: optimise size
    public static byte[] buffer1;
    public static byte[] buffer2;
    //public static byte[] buffer3; // todo: remove?
    
    // Helper objects for fast multiplication of two large numbers (without modulo)
    public static boolean FLAG_FAST_MULT_VIA_RSA = false;
    public static short MULT_RSA_ENGINE_MAX_LENGTH_BITS= (short) 768; 
    public static byte[] CONST_TWO = {0x02};
    
    public static KeyPair rsa_keypair = null;
    public static RSAPublicKey rsa_pubkey_pow2 = null;
    public static Cipher rsa_cipher = null;
    
    // initialize static objects. Should be done only once, e.g. in applet constructor
    public static void init(){
        // init arrays
        try {
            buffer1 = JCSystem.makeTransientByteArray((short) BUFFER_SIZE, JCSystem.CLEAR_ON_DESELECT);
        } catch (SystemException e) {
            buffer1 = new byte[BUFFER_SIZE];
        }
        try {
            buffer2 = JCSystem.makeTransientByteArray((short) BUFFER_SIZE, JCSystem.CLEAR_ON_DESELECT);
        } catch (SystemException e) {
            buffer2 = new byte[BUFFER_SIZE];
        }
//        try {
//            buffer3 = JCSystem.makeTransientByteArray((short) BUFFER_SIZE, JCSystem.CLEAR_ON_DESELECT);
//        } catch (SystemException e) {
//            buffer3 = new byte[BUFFER_SIZE];
//        }
        // RSA engine for fast multiplication
        rsa_keypair = new KeyPair(KeyPair.ALG_RSA_CRT, MULT_RSA_ENGINE_MAX_LENGTH_BITS);
        rsa_keypair.genKeyPair();
        rsa_pubkey_pow2 = (RSAPublicKey) rsa_keypair.getPublic();
        rsa_pubkey_pow2.setExponent(CONST_TWO, (short) 0, (short) CONST_TWO.length);
        rsa_cipher = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);

        FLAG_FAST_MULT_VIA_RSA = false; // set true only if succesfully allocated and tested below
        try { // Subsequent code may fail on some real (e.g., Infineon CJTOP80K) cards - catch exception
            rsa_cipher.init(rsa_pubkey_pow2, Cipher.MODE_ENCRYPT);
            // Try operation - if doesn't work, exception SW_CANTALLOCATE_BIGNAT is emitted
            Util.arrayFillNonAtomic(buffer1, (short) 0, (short) buffer1.length, (byte) 6);
            rsa_cipher.doFinal(buffer1, (short) 0, (short) buffer1.length, buffer1, (short) 0);
            FLAG_FAST_MULT_VIA_RSA = true;
        } catch (Exception ignored) {
        } // discard exception      
        
    }
    
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
        //TODO: make it time-constant!
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
        // todo: make it time constant!
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
        // todo: make it time constant!
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
        // todo: make it time constant?
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
        // todo: make it time constant?
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
    
    /**
     *  UNDER CONSTRUCTION   
     *  Biginteger multiplication and modulo computation
     *  Based on https://github.com/OpenCryptoProject/JCMathLib
     *  Code simplified to only support methods necessary for multiplication and modulo
     */
    
    /**
     * Performs multiplication of two bignats x and y and stores result into z. 
     * RSA engine is used to speedup operation for large values.
     * Idea of speedup: 
     * We need to mutiply x.y where both x and y are 32B 
     * (x + y)^2 == x^2 + y^2 + 2xy 
     * Fast RSA engine is available (a^b mod n) 
     * n can be set bigger than 64B => a^b mod n == a^b 
     * [(x + y)^2 mod n] - [x^2 mod n] - [y^2 mod n] => 2xy where [] means single RSA operation 
     * 2xy / 2 => result of mult(x,y) 
     * Note: if multiplication is used with either x or y argument same repeatedly, 
     * [x^2 mod n] or [y^2 mod n] can be precomputed and passed as arguments x_pow_2 or y_pow_2
     *
     * @param x first value to multiply
     * @param y second value to multiply
     * @param x_pow_2 if not null, array with precomputed value x^2 is expected
     * @param y_pow_2 if not null, array with precomputed value y^2 is expected
     * @return z size
     */
    public static short mult_rsa_trick(byte[] x, short offsetx, byte[] y, short offsety, short size, byte[] z, short offsetz) {
        // todo: 
        //check z size >= sizex*2
        // check size x, y
        
        // x+y => buffer1
        Util.arrayFillNonAtomic(buffer1, (short) 0, (short) buffer1.length, (byte) 0);
        
        // copy x (retains MSBF order)
        short offsetb1= (short)(buffer1.length-size);
        Util.arrayCopyNonAtomic(x, offsetx, buffer1, offsetb1, size);
        
        // copy y
        short offsetb2= (short)(buffer2.length-size);
        Util.arrayFillNonAtomic(buffer2, (short) 0, (short) buffer2.length, (byte) 0);
        Util.arrayCopyNonAtomic(y, offsety, buffer2, offsetb2, size);
        
        // add y into buffer1
        boolean carry= add_carry(buffer1, (short)0, buffer2, (short)0, (short)buffer1.length);
        // should be no carry since buffer are sufficiently large
        
        // ((x+y)^2) => buffer1
        rsa_cipher.doFinal(buffer1, (byte) 0, (short) buffer1.length, buffer1, (short) 0);
        
        // y^2 => buffer2
        // y is already present in buffer2
        //Util.arrayFillNonAtomic(buffer2, (short) 0, (short) buffer2.length, (byte) 0);
        //offsetb2= (short) (buffer2.length - size);
        //Util.arrayCopyNonAtomic(y, offsety, buffer2, offsetb2, size);
        rsa_cipher.doFinal(buffer2, (byte) 0, (short) buffer2.length, buffer2, (short) 0);
        
        // ((x+y)^2) - y^2 => buffer1
        carry= subtract(buffer1, (short)0, buffer2, (short)0, (short)buffer1.length);
        // todo: carry should be false
        
        // x^2 => buffer2
        // todo: support x^2 precomputation if reused multiple times
        Util.arrayFillNonAtomic(buffer2, (short) 0, (short) buffer2.length, (byte) 0);
        offsetb2= (short) (buffer2.length - size);
        Util.arrayCopyNonAtomic(x, offsetx, buffer2, offsetb2, size);
        rsa_cipher.doFinal(buffer2, (byte) 0, (short) buffer2.length, buffer2, (short) 0);
            
        // ((x+y)^2) - y^2 - x^2 => buffer1
        carry= subtract(buffer1, (short)0, buffer2, (short)0, (short)buffer1.length);
        // todo: carry should be false
        
        // we now have 2xy in buffer1, divide it by 2 => shift by one bit and fill back into z
        short res = 0;
        short res2 = 0;
        for (short offset = (short)(buffer1.length - 1); offset >= 1; offset--) {
            res = (short) (buffer1[offset] & 0xff);
            res = (short) (res >> 1);
            res2 = (short) (buffer1[(short)(offset - 1)] & 0xff);
            res2 = (short) (res2 << 7);
            z[(short)(offsetz+offset)] = (byte) (short) (res | res2);
        }
        res = (short) (buffer1[0] & 0xff);
        res = (short) (res >> 1);
        z[offsetz]= (byte)res;
        return (short)buffer1.length;
        
        // todo: optimization: for 32bytes mult, bytes 0 to 31 (out of 96) should be 0 => skip computations?
    }    
    
    /**
     * Compute x mod y
     * <P>
     * x and y are copied to local arrays Biginteger.buffer1 and Biginteger.buffer2.
     * After computation, modulo is located in x buffer, at provided offset and size.
     * After computation, x may contain many leading zeros, this can be further processed 
     * using the shrink() method.
     * <P>
     * Uses schoolbook division inside and has O^2 complexity in the difference
     * of significant digits of the divident (in this number) and the divisor.
     * For numbers of equal size complexity is linear.
     * 
     * @param x
     * @param y must be non-zero
     * 
     * @return size of Biginteger x
     */
    // computes x mod y store to z at offsetz
    public static short mod(byte[] x, short offsetx, short sizex, byte[] y, short offsety, short sizey) {
        // todo: check sizex and sizey < buffer1.length
        
        
        // copy x to buffer1 in RAM memory if needed
        if (x != buffer1 || offsetx != (short)0){
            Util.arrayCopyNonAtomic(x, offsetx, buffer1, (short)0, sizex);
        }
        //x= buffer1;
        //offsetx= 0;
        byte[] dividend= buffer1;
        short dividend_offset= 0;
        short dividend_size= sizex;
        
        // copy y to buffer2 in RAM memory if needed
        if (y != buffer2 || offsety != (short)0){
            Util.arrayCopyNonAtomic(y, offsety, buffer2, (short)0, sizey);
        }
        byte[] divisor= buffer2;
        short divisor_offset= 0;
        short divisor_size= sizey;
        
         // divisor_index is the first nonzero digit (short) in the divisor
         short divisor_index = 0;
         while (divisor[divisor_index] == 0) {
             divisor_index++;
         }

         // The size of this might be different from divisor. Therefore,
         // for the first subtraction round we have to shift the divisor
         // divisor_shift = this.size - divisor.size + divisor_index
         // digits to the left. If this amount is negative, then
         // this is already smaller then divisor and we are done.
         // Below we do divisor_shift + 1 subtraction rounds. As an
         // additional loop index we also count the rounds (from
         // zero upwards) in division_round. This gives access to the
         // first remaining divident digits.
         short divisor_shift = (short) (dividend_size - divisor_size + divisor_index);
         short division_round = 0;

         // We could express now a size constraint, namely that
         // divisor_shift + 1 <= quotient.size
         // However, in the proof protocol we divide x / v, where
         // x has 2*n digits when v has n digits. There the above size
         // constraint is violated, the division is however valid, because
         // it will always hold that x < v * (v - 1) and therefore the
         // quotient will always fit into n digits.
         // System.out.format("XX this size %d div ind %d div shift %d " +
         // "quo size %d\n" +
         // "%s / %s\n",
         // this.size,
         // divisor_index,
         // divisor_shift,
         // quotient != null ? quotient.size : -1,
         // this.to_hex_string(),
         // divisor.to_hex_string());
         // The first digits of the divisor are needed in every
         // subtraction round.
         short first_divisor_digit = (short) (divisor[divisor_index] & digit_mask);
         short divisor_bit_shift = (short) (highest_bit((short) (first_divisor_digit + 1)) - 1);
         byte second_divisor_digit = divisor_index < (short) (divisor_size - 1) ? divisor[(short) (divisor_index + 1)]
                 : 0;
         byte third_divisor_digit = divisor_index < (short) (divisor_size - 2) ? divisor[(short) (divisor_index + 2)]
                 : 0;

         // The following variables are used inside the loop only.
         // Declared here as optimization.
         // divident_digits and divisor_digit hold the first one or two
         // digits. Needed to compute the multiple of the divisor to
         // subtract from this.
         short divident_digits, divisor_digit;

         // To increase precision the first digits are shifted to the
         // left or right a bit. The following variables compute the shift.
         short divident_bit_shift, bit_shift;

         // Declaration of the multiple, with which the divident is
         // multiplied in each round and the quotient_digit. Both are
         // a single digit, but declared as a double digit to avoid the
         // trouble with negative numbers. If quotient != null multiple is
         // added to the quotient. This addition is done with quotient_digit.
         short multiple, quotient_digit;
         short numLoops = 0;
         short numLoops2 = 0;
         while (divisor_shift >= 0) {
             numLoops++; // CTO number of outer loops is constant (for given length of divisor)
             // Keep subtracting from this until
             // divisor * 2^(8 * divisor_shift) is bigger than this.
             while (!shift_lesser(dividend, dividend_offset, dividend_size, 
                                 divisor, divisor_offset, divisor_size, 
                                 divisor_shift, (short) (division_round > 0 ? division_round - 1 : 0))) 
             {
                 numLoops2++; // BUGBUG: CTO - number of these loops fluctuates heavily => strong impact on operation time 
                 // this is bigger or equal than the shifted divisor.
                 // Need to subtract some multiple of divisor from this.
                 // Make a conservative estimation of the multiple to subtract.
                 // We estimate a lower bound to avoid underflow, and continue
                 // to subtract until the remainder in this gets smaller than
                 // the shifted divisor.
                 // For the estimation get first the two relevant digits
                 // from this and the first relevant digit from divisor.
                 divident_digits = division_round == 0 ? 0
                         : (short) ((short) (dividend[(short) (division_round - 1)]) << digit_len);
                 divident_digits |= (short) (dividend[division_round] & digit_mask);

                 // The multiple to subtract from this is
                 // divident_digits / divisor_digit, but there are two
                 // complications:
                 // 1. divident_digits might be negative,
                 // 2. both might be very small, in which case the estimated
                 // multiple is very inaccurate.
                 if (divident_digits < 0) {
                         // case 1: shift both one bit to the right
                     // In standard java (ie. in the test frame) the operation
                     // for >>= and >>>= seems to be done in integers,
                     // even if the left hand side is a short. Therefore,
                     // for a short left hand side there is no difference
                     // between >>= and >>>= !!!
                     // Do it the complicated way then.
                     divident_digits = (short) ((divident_digits >>> 1) & positive_double_digit_mask);
                     divisor_digit = (short) ((first_divisor_digit >>> 1) & positive_double_digit_mask);
                 } else {
                         // To avoid case 2 shift both to the left
                     // and add relevant bits.
                     divident_bit_shift = (short) (highest_bit(divident_digits) - 1);
                         // Below we add one to divisor_digit to avoid underflow.
                     // Take therefore the highest bit of divisor_digit + 1
                     // to avoid running into the negatives.
                     bit_shift = divident_bit_shift <= divisor_bit_shift ? divident_bit_shift
                             : divisor_bit_shift;

                     divident_digits = shift_bits(
                             divident_digits,
                             division_round < (short) (dividend_size - 1) ? dividend[(short) (division_round + 1)]
                                     : 0,
                             division_round < (short) (dividend_size - 2) ? dividend[(short) (division_round + 2)]
                                     : 0, bit_shift);
                     divisor_digit = shift_bits(first_divisor_digit,
                             second_divisor_digit, third_divisor_digit,
                             bit_shift);

                 }

                 // add one to divisor to avoid underflow
                 multiple = (short) (divident_digits / (short) (divisor_digit + 1));

                 // Our strategy to avoid underflow might yield multiple == 0.
                 // We know however, that divident >= divisor, therefore make
                 // sure multiple is at least 1.
                 if (multiple < 1) {
                     multiple = 1;
                 }

                 //times_minus(divisor, divisor_shift, multiple);
                 times_minus(dividend, dividend_offset, dividend_size, divisor, divisor_offset, divisor_size, divisor_shift, multiple);
             }

             // treat loop indices
             division_round++;
             divisor_shift--;
         }
         // at this point, mod is in buffer1, copy back to x
         if (buffer1 != x || offsetx != (short)0){
             Util.arrayCopyNonAtomic(buffer1, (short)0, x, offsetx, sizex);
         }
         return sizex;
     }
    
    /**
     * Helper functions for mod() function
     */
    
    
    /**
     * Index of the most significant 1 bit.
     * <P>
     * {@code x} has type short.
     * <P>
     * Utility method, used in division.
     * 
     * @param x
     *            of type short
     * @return index of the most significant 1 bit in {@code x}, returns
     *         {@link #double_digit_len} for {@code x == 0}.
     */
    private static short highest_bit(short x) {
        // todo: make it time constant!
        for (short i = 0; i < double_digit_len; i++) {
            if (x < 0) {
                return i;
            }
            x <<= 1;
        }
        return double_digit_len;
    }
    
    /**
     * Shift to the left and fill. Takes {@code high} {@code middle} {@code low}
     * as 4 digits, shifts them {@code shift} bits to the left and returns the
     * most significant {@link #double_digit_len} bits.
     * <P>
     * Utility method, used in division.
     * 
     * 
     * @param high
     *            of type short, most significant {@link #double_digit_len} bits
     * @param middle
     *            of type byte, middle {@link #digit_len} bits
     * @param low
     *            of type byte, least significant {@link #digit_len} bits
     * @param shift
     *            amount of left shift
     * @return most significant {@link #double_digit_len} as short
     */
     private static short shift_bits(short high, byte middle, byte low,
                     short shift) {
         // shift high
         high <<= shift;

         // merge middle bits
         byte mask = (byte) (digit_mask << (shift >= digit_len ? 0 : digit_len
                         - shift));
         short bits = (short) ((short) (middle & mask) & digit_mask);
         if (shift > digit_len) {
             bits <<= shift - digit_len;
         }
         else {
             bits >>>= digit_len - shift;
         }
         high |= bits;

         if (shift <= digit_len) {
             return high;
         }

         // merge low bits
         mask = (byte) (digit_mask << double_digit_len - shift);
         bits = (short) ((((short) (low & mask) & digit_mask) >> double_digit_len - shift));
         high |= bits;

         return high;
     }
    
    /**
     * Return the number of leading zeroes (if any) from Biginteger value 
     */
    public static short shrink(byte[] x, short offsetx, short sizex) {
        // todo: make it time constant!
        short i = 0;
        for (i = 0; i < sizex; i++) { // Find first non-zero byte
            if (x[(short)(offsetx+i)] != (byte)0) {
                break;
            }
        }

        // return number of zero elements that can be skipped
        // new_offset will be offset+i, new_size is size-i
        return i; 
    }
     
    /**
     * Scaled comparison. Compares this number with {@code other * 2^(}
     * {@link #digit_len} {@code * shift)}. That is, shifts {@code other}
     * {@code shift} digits to the left and compares then. This bignat and
     * {@code other} will not be modified inside this method.
     * <P>
     * 
     * As optimization {@code start} can be greater than zero to skip the first
     * {@code start} digits in the comparison. These first digits must be zero
     * then, otherwise an assertion is thrown. (So the optimization takes only
     * effect when <a
     * href="../../../overview-summary.html#NO_CARD_ASSERT">NO_CARD_ASSERT</a>
     * is defined.)
     * 
     * @param x, offsetx, sizex
     *            First Biginteger to compare
     * @param other, offset_other, size_other
     *            Bignat to compare to
     * @param shift
     *            left shift of other before the comparison
     * @param start
     *            digits to skip at the beginning
     * @return true if this number is strictly less than the shifted
     *         {@code other}, false otherwise.
     */
     public static boolean shift_lesser(byte[] x, short offsetx, short sizex, byte[] other, short offset_other, short size_other, short shift, short start) {
         short j = (short) (size_other + shift - sizex + start);
         short x_short, other_short;
         for (short i = start; i < sizex; i++, j++) {
             x_short = (short) (x[i] & digit_mask);
             if (j >= 0 && j < size_other) {
                 other_short = (short) (other[j] & digit_mask);
             }
             else {
                 other_short = 0;
             }
             if (x_short < other_short) {
                 return true; // CTO
             }
             if (x_short > other_short) {
                 return false;
             }
         }
         return false;
     }
           
      /**
       * Scaled subtraction. Subtracts {@code mult * 2^(}{@link #digit_len}
       * {@code  * shift) * other} from this.
       * <P>
       * That is, shifts {@code mult * other} precisely {@code shift} digits to
       * the left and subtracts that value from this. {@code mult} must be less
       * than {@link #bignat_base}, that is, it must fit into one digit. It is
       * only declared as short here to avoid negative values.
       * <P>
       * {@code mult} has type short.
       * <P>
       * No size constraint. However, an assertion is thrown, if the result would
       * be negative. {@code other} can have more digits than this object, but
       * then sufficiently many leading digits must be zero to avoid the
       * underflow.
       * <P>
       * Used in division.
       * 
       * @param x, offsetx, sizex: 
       *            First Biginteger operand
       * @param other, other_offset, other_size
       *            Biginteger to subtract from first Biginteger
       * @param shift
       *            number of digits to shift {@code other} to the left
       * @param mult
       *            of type short, multiple of {@code other} to subtract from this
       *            object. Must be below {@link #bignat_base}.
       */
     public static void times_minus(byte[] x, short offsetx, short sizex, byte[] other, short other_offset, short other_size, short shift, short mult) {
       short akku = 0;
       short subtraction_result;
       short i = (short) (sizex - 1 - shift);
       short j = (short) (other_size - 1);
       for (; i >= 0 && j >= 0; i--, j--) {
           akku = (short) (akku + (short) (mult * (other[j] & digit_mask)));
           subtraction_result = (short) ((x[i] & digit_mask) - (akku & digit_mask));
    
           x[i] = (byte) (subtraction_result & digit_mask);
           akku = (short) ((akku >> digit_len) & digit_mask);
           if (subtraction_result < 0) {
               akku++;
           }
       }
    
       // deal with carry as long as there are digits left in this
       while (i >= 0 && akku != 0) {
           subtraction_result = (short) ((x[i] & digit_mask) - (akku & digit_mask));
           x[i] = (byte) (subtraction_result & digit_mask);
           akku = (short) ((akku >> digit_len) & digit_mask);
           if (subtraction_result < 0) {
               akku++;
           }
           i--;
       }
     }
    
}