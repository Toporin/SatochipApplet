/*
*******************************************************************************    
*   Satochip Hardware Wallet
*   Sources available on https://github.com/Toporin
*   
*   Based on BTChip Bitcoin Hardware Wallet Java Card implementation
*   (c) 2013 BTChip - 1BTChip7VfTnrPra5jqci7ejnMguuHogTn   
*
*   This program is free software: you can redistribute it and/or modify
*   it under the terms of the GNU Affero General Public License as
*   published by the Free Software Foundation, either version 3 of the
*   License, or (at your option) any later version.
*
*   This program is distributed in the hope that it will be useful,
*   but WITHOUT ANY WARRANTY; without even the implied warranty of
*   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*   GNU Affero General Public License for more details.
*
*   You should have received a copy of the GNU Affero General Public License
*   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*******************************************************************************   
*/    

package org.satochip.applet;

import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.MessageDigest;

/**
 * Bitcoin SegWit transaction parsing
 *
 */
public class SegwitTransaction {
    
    // static data storing contextual information
    private static short[] ctx2;
    protected static byte[] ctx;
    protected static MessageDigest digestFull;
    
    // state 
    public static final byte STATE_RECEIVED_NONE = (byte)0x01;
    public static final byte STATE_RECEIVED_HASHSEQUENCE = (byte)0x02;
    public static final byte STATE_RECEIVED_OUTPOINT = (byte)0x03;
    public static final byte STATE_HASHING_SCRIPTCODE = (byte)0x04;
    public static final byte STATE_RECEIVED_SCRIPTCODE = (byte)0x05;
    public static final byte STATE_PARSED = (byte)0x06;
    public static final byte STATE_WAITING_OUTPUT = (byte) 0x07;
    
    // return value during parsing
    public static final byte RESULT_FINISHED = (byte)0x13;
    public static final byte RESULT_ERROR = (byte)0x79;
    public static final byte RESULT_MORE = (byte)0x00;

    // Transaction context
    protected static final byte SIZEOF_U32 = 4;
    protected static final byte SIZEOF_U8 = 1;
    protected static final byte SIZEOF_AMOUNT = 8;
    
    // context data (short size)
    private static final byte CURRENT = (byte)0;
    private static final byte REMAINING = (byte)1;
    private static final byte NBOUTPUTS = (byte)2;
    
    // context data (byte size)
    protected static final byte CTX_STATE_PARSE_TX = (short)(0);
    protected static final byte CTX_STATE_PARSE_OUTPUTS = (short)(CTX_STATE_PARSE_TX + SIZEOF_U8);
    protected static final byte CTX_SCRIPT_REMAINING = (short)(CTX_STATE_PARSE_OUTPUTS + SIZEOF_U8);
    protected static final byte CTX_OUTPUT_AMOUNT = (short)(CTX_SCRIPT_REMAINING + SIZEOF_U32);
    protected static final byte CTX_INPUT_AMOUNT = (short)(CTX_OUTPUT_AMOUNT + SIZEOF_AMOUNT);
    protected static final byte CTX_TMP_BUFFER = (short)(CTX_INPUT_AMOUNT + SIZEOF_AMOUNT);
    protected static final byte CTX_CONTEXT_SIZE = (short)(CTX_TMP_BUFFER + SIZEOF_AMOUNT);  

    public static void init() {
        ctx2 = JCSystem.makeTransientShortArray((short)3, JCSystem.CLEAR_ON_DESELECT);
        ctx = JCSystem.makeTransientByteArray(CTX_CONTEXT_SIZE, JCSystem.CLEAR_ON_DESELECT);
        digestFull = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
    }
    
    public static void resetTransaction(){
        ctx[CTX_STATE_PARSE_OUTPUTS] = STATE_RECEIVED_NONE;    
        ctx[CTX_STATE_PARSE_TX] = STATE_RECEIVED_NONE; 
        ctx2[NBOUTPUTS]=(short)-1;    
        Biginteger.setZero(ctx, CTX_SCRIPT_REMAINING, (short)4);
        Biginteger.setZero(ctx, CTX_OUTPUT_AMOUNT, (short)8);
        Biginteger.setZero(ctx, CTX_INPUT_AMOUNT, (short)8);
        Biginteger.setZero(ctx, CTX_TMP_BUFFER, (short)8);
        digestFull.reset();
        return;
    }
    
    private static void consumeTransaction(byte buffer[], short length) {
        digestFull.update(buffer, ctx2[CURRENT], length);
        ctx2[REMAINING] -= length;
        ctx2[CURRENT] += length;
    }
    
    private static boolean parseVarint(byte[] buffer, byte[] target, short targetOffset) {
        if (ctx2[REMAINING] < (short)1) {
            return false;
        }
        short firstByte = (short)(buffer[ctx2[CURRENT]] & 0xff);
        if (firstByte < (short)0xfd) {
            Biginteger.setByte(target, targetOffset, (short)4, (byte)firstByte);
            consumeTransaction(buffer, (short)1);            
        }
        else
        if (firstByte == (short)0xfd) {
            consumeTransaction(buffer, (short)1);
            if (ctx2[REMAINING] < (short)2) {
                return false;
            }
            target[targetOffset]=0x00;
            target[(short)(targetOffset+1)]=0x00;
            target[(short)(targetOffset+2)]=buffer[(short)(ctx2[CURRENT] + 1)];
            target[(short)(targetOffset+3)]=buffer[ctx2[CURRENT]];
            consumeTransaction(buffer, (short)2);
        }
        else
        if (firstByte == (short)0xfe) {
            consumeTransaction(buffer, (short)1);
            if (ctx2[REMAINING] < (short)4) { 
                return false;
            }
            target[targetOffset]=buffer[(short)(ctx2[CURRENT] + 3)];
            target[(short)(targetOffset+1)]=buffer[(short)(ctx2[CURRENT] + 2)];
            target[(short)(targetOffset+2)]=buffer[(short)(ctx2[CURRENT] + 1)];
            target[(short)(targetOffset+3)]=buffer[ctx2[CURRENT]];
            consumeTransaction(buffer, (short)4);
        }
        else {
            return false;
        }
        return true;
    }
    
    /*
    * Parse a list outputs.
    * An output consists of: output= [amount(8b) + script_size(varint) + script]
    */
    public static byte parseOutputs(byte buffer[], short offset, short remaining, short nbOutputs) {
        ctx2[CURRENT] = offset;
        ctx2[REMAINING] = remaining;
        for (;;) {
            if (ctx[CTX_STATE_PARSE_OUTPUTS] == STATE_RECEIVED_NONE) {
                // set number of outputs
                ctx2[NBOUTPUTS]=nbOutputs;
                ctx[CTX_STATE_PARSE_OUTPUTS] = STATE_WAITING_OUTPUT;               
            }
            if (ctx[CTX_STATE_PARSE_OUTPUTS] == STATE_WAITING_OUTPUT) {
            	if (ctx2[NBOUTPUTS]==0) {
                    // No more outputs to hash, move forward
                    ctx[CTX_STATE_PARSE_OUTPUTS] = STATE_PARSED;
                    return RESULT_FINISHED;
                }
                if (ctx2[REMAINING] < (short)1) {
                    // No more data to read, ok
                    return RESULT_MORE;
                }
                // Amount
                if (ctx2[REMAINING] < (short)8) {
                    return RESULT_ERROR;
                }
                Biginteger.swap(buffer, ctx2[CURRENT], ctx, CTX_TMP_BUFFER, (short)8);
                Biginteger.add_carry(ctx, CTX_OUTPUT_AMOUNT, ctx, CTX_TMP_BUFFER, (short)8);
                consumeTransaction(buffer, (short)8);
                // Read the script length
                if (!parseVarint(buffer, ctx, CTX_SCRIPT_REMAINING)) {
                    return RESULT_ERROR;
                }
                ctx[CTX_STATE_PARSE_OUTPUTS] = STATE_HASHING_SCRIPTCODE;
            } 
            if (ctx[CTX_STATE_PARSE_OUTPUTS] == STATE_HASHING_SCRIPTCODE) {
                if (ctx2[REMAINING] < (short)1) {
                    return RESULT_MORE; // No more data to read, ok
                }
                if (Biginteger.equalZero(ctx,CTX_SCRIPT_REMAINING, (short)4)) {
                    // Move to next output
                    ctx2[NBOUTPUTS]=(short)(ctx2[NBOUTPUTS]-1);
                    ctx[CTX_STATE_PARSE_OUTPUTS] = STATE_WAITING_OUTPUT;
                    continue;
                }
                short scriptRemaining = Biginteger.getLSB(ctx, CTX_SCRIPT_REMAINING,(short)4);
                short dataAvailable = (ctx2[REMAINING] > scriptRemaining ? scriptRemaining : ctx2[REMAINING]);
                if (dataAvailable == 0) {
                    return RESULT_MORE;
                }
                consumeTransaction(buffer, dataAvailable);
                Biginteger.setByte(ctx, CTX_TMP_BUFFER, (short)4, (byte)dataAvailable);
                Biginteger.subtract(ctx, CTX_SCRIPT_REMAINING, ctx, CTX_TMP_BUFFER,(short)4);
                // at this point the program loop until either the script or the buffer is consumed
            } 
        }//endfor
    }
    
    
    /*
    * a segwith tx preimage consists of:
    * preImage= [nVersion(4b) + hasPrevouts(32b) + hashSequence(32b) + outpoint(36b) + scriptCode(varInt)
    *                 + amount(8b) + nsequence(4b) + hashOutputs(32b) + nLocktime(4b) + nHashType(4b)]
    */
    public static byte parseTransaction(byte buffer[], short offset, short remaining) {
        ctx2[CURRENT] = offset;
        ctx2[REMAINING] = remaining;
        for (;;) {
            if (ctx[CTX_STATE_PARSE_TX] == STATE_RECEIVED_NONE) {
                // check that outputs have been parsed previously
                if (ctx[CTX_STATE_PARSE_OUTPUTS] != STATE_PARSED){
                    return RESULT_ERROR;// todo: specific error code?
                }
                // nVersion
                if (ctx2[REMAINING] < (short)4) {
                    return RESULT_ERROR;
                }
                consumeTransaction(buffer, (short)4);
                // hashPrevouts
                if (ctx2[REMAINING] < (short)32) {
                    return RESULT_ERROR;
                }
                consumeTransaction(buffer, (short)32);
                // hashSequence
                if (ctx2[REMAINING] < (short)32) {
                    return RESULT_ERROR;
                }
                consumeTransaction(buffer, (short)32);
                
                ctx[CTX_STATE_PARSE_TX] = STATE_RECEIVED_HASHSEQUENCE; 
                if (ctx2[REMAINING] < (short)1) {
                    return RESULT_MORE; // No more data to read, ok
                }
            }
            if (ctx[CTX_STATE_PARSE_TX] == STATE_RECEIVED_HASHSEQUENCE) {
                
                // parse outpoint: TxOutHash
                if (ctx2[REMAINING] < (short)32) {
                    return RESULT_ERROR;
                }
                consumeTransaction(buffer, (short)32);
                
                // parse outpoint: TxOutHashIndex
                if (ctx2[REMAINING] < (short)4) {
                    return RESULT_ERROR;
                }
                consumeTransaction(buffer, (short)4);
                
                ctx[CTX_STATE_PARSE_TX] = STATE_RECEIVED_OUTPOINT;                
                if (ctx2[REMAINING] < (short)1) {
                    return RESULT_MORE; // No more data to read, ok
                }
            }    
            if (ctx[CTX_STATE_PARSE_TX] == STATE_RECEIVED_OUTPOINT) {
                // Read the script length
                if (!parseVarint(buffer, ctx, CTX_SCRIPT_REMAINING)) {
                    return RESULT_ERROR;
                }
                ctx[CTX_STATE_PARSE_TX] = STATE_HASHING_SCRIPTCODE;
            }
            if (ctx[CTX_STATE_PARSE_TX] == STATE_HASHING_SCRIPTCODE) {
                if (ctx2[REMAINING] < (short)1) {
                    return RESULT_MORE; // No more data to read, ok
                }
                // if script size is zero or script is already consumed 
                if (Biginteger.equalZero(ctx,CTX_SCRIPT_REMAINING,(short)4)) {
                    ctx[CTX_STATE_PARSE_TX] = STATE_RECEIVED_SCRIPTCODE;
                    continue;
                }
                short scriptRemaining = Biginteger.getLSB(ctx, CTX_SCRIPT_REMAINING,(short)4); 
                short dataAvailable = (ctx2[REMAINING] > scriptRemaining ? scriptRemaining : ctx2[REMAINING]);
                if (dataAvailable == 0) {
                    return RESULT_MORE;
                }
                consumeTransaction(buffer, dataAvailable);
                Biginteger.setByte(ctx, CTX_TMP_BUFFER, (short)4, (byte)dataAvailable);
                Biginteger.subtract(ctx, CTX_SCRIPT_REMAINING, ctx, CTX_TMP_BUFFER, (short)4);
                // at this point the program loop until either the script or the buffer is consumed
            }
            if (ctx[CTX_STATE_PARSE_TX] == STATE_RECEIVED_SCRIPTCODE) {    
                if (ctx2[REMAINING] < (short)1) {
                    return RESULT_MORE; // No more data to read, ok
                }
                // amount
                if (ctx2[REMAINING] < (short)8) {
                    return RESULT_ERROR;
                }
                consumeTransaction(buffer, (short)8);
                // Sequence
                if (ctx2[REMAINING] < (short)4) {
                    return RESULT_ERROR;
                }
                consumeTransaction(buffer, (short)4);// todo: enforce sequence
                // hashOutput
                if (ctx2[REMAINING] < (short)32) {
                    return RESULT_ERROR;
                }
                consumeTransaction(buffer, (short)32); // todo:enforce hashOutput
                // nLocktime
                if (ctx2[REMAINING] < (short)4) {
                    return RESULT_ERROR;
                }
                consumeTransaction(buffer, (short)4);
                // nHashType
                if (ctx2[REMAINING] < (short)4) {
                    return RESULT_ERROR;
                }
                consumeTransaction(buffer, (short)4);
                ctx[CTX_STATE_PARSE_TX] = STATE_PARSED;
                return RESULT_FINISHED;
            }        
        }// end for
    }

} //end class
