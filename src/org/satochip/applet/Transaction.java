/*  
 *   SatoChip: Bitcoin Hardware Wallet based on javacard
 *   (c) 2015-2019 by Toporin - 16DMCk4WUaHofchAhpMaQS4UPm4urcy2dN
 *   Sources available on https://github.com/Toporin    
 * 
 *   Bitcoin transaction parser derived from:
 *   BTChip Bitcoin Hardware Wallet Java Card implementation
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
 *   
 */    

package org.satochip.applet;

import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.MessageDigest;

/**
 * Bitcoin transaction parsing
 * @author BTChip
 *
 */
public class Transaction {
    
    public static void init() {
        ctx = JCSystem.makeTransientByteArray(TX_CONTEXT_SIZE, JCSystem.CLEAR_ON_DESELECT);
        ctx2 = JCSystem.makeTransientShortArray((short)3, JCSystem.CLEAR_ON_DESELECT);
        digestFull = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
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
    
    public static void resetTransaction(){
            ctx[TX_STATE] = STATE_NONE;          
            Biginteger.setZero(ctx, TX_REMAINING_I, (short)4);
            Biginteger.setZero(ctx, TX_REMAINING_O, (short)4);
            Biginteger.setZero(ctx, TX_CURRENT_I, (short)4);
            Biginteger.setZero(ctx, TX_CURRENT_O, (short)4);
            Biginteger.setZero(ctx, TX_SCRIPT_REMAINING, (short)4);
            Biginteger.setZero(ctx, TX_AMOUNT, (short)8);
            Biginteger.setZero(ctx, TX_SCRIPT_COORD, (short)4);
            Biginteger.setZero(ctx, TX_TMP_BUFFER, (short)8);
            ctx[TX_SCRIPT_ACTIVE] = INACTIVE;
            digestFull.reset();
            return;
    }
       
    public static byte parseTransaction(byte buffer[], short offset, short remaining) {
        ctx2[CURRENT] = offset;
        ctx2[REMAINING] = remaining;
        for (;;) {
            if (ctx[TX_STATE] == STATE_NONE) {
                
                // Parse the beginning of the transaction
                // Version
                if (ctx2[REMAINING] < (short)4) {
                    return RESULT_ERROR;
                }
                consumeTransaction(buffer, (short)4);
                // Number of inputs
                if (!parseVarint(buffer, ctx, TX_REMAINING_I)) {
                    return RESULT_ERROR;
                }
                ctx[TX_STATE] = STATE_WAIT_INPUT;
            }
            if (ctx[TX_STATE] == STATE_WAIT_INPUT) {
                if (Biginteger.equalZero(ctx, TX_REMAINING_I,(short)4)) {   
                    if (ctx[TX_SCRIPT_ACTIVE]== INACTIVE){
                        // there should be exactly one input script active at this point
                        return RESULT_ERROR;
                    }
                    // No more inputs to hash, move forward
                    ctx[TX_STATE] = STATE_HASHING_INPUT_DONE;
                    continue;
                }
                if (ctx2[REMAINING] < (short)1) {
                    // No more data to read, ok
                    return RESULT_MORE;
                }
                // Proceed with the next input
                if (ctx2[REMAINING] < (short)36) { // prevout : 32 hash + 4 index
                    return RESULT_ERROR;
                }
                consumeTransaction(buffer, (short)36);
                // Read the script length
                if (!parseVarint(buffer, ctx, TX_SCRIPT_REMAINING)) {
                    return RESULT_ERROR;
                }
                else if (!Biginteger.equalZero(ctx,TX_SCRIPT_REMAINING, (short)4)){
                    // check if a script was already present
                    if (ctx[TX_SCRIPT_ACTIVE]== INACTIVE){
                        ctx[TX_SCRIPT_ACTIVE]= ACTIVE;
                        Util.arrayCopyNonAtomic(ctx, TX_CURRENT_I, ctx, TX_SCRIPT_COORD, SIZEOF_U32); 
                    }
                    else { // there should be only one input script active
                        return RESULT_ERROR;
                    }
                }
                ctx[TX_STATE] = STATE_HASHING_INPUT_SCRIPT;                
            }
            if (ctx[TX_STATE] == STATE_HASHING_INPUT_SCRIPT) {
                if (ctx2[REMAINING] < (short)1) {
                    // No more data to read, ok
                    return RESULT_MORE;
                }
                // if script size is zero or script is already consumed 
                if (Biginteger.equalZero(ctx,TX_SCRIPT_REMAINING,(short)4)) {
                    // Sequence
                    if (ctx2[REMAINING] < (short)4) {
                        return RESULT_ERROR;
                    }
                    // TODO : enforce sequence
                    consumeTransaction(buffer, (short)4);
                    // Move to next input
                    Biginteger.subtract1_carry(ctx, TX_REMAINING_I,(short)4);
                    Biginteger.add1_carry(ctx, TX_CURRENT_I, (short)4);
                    ctx[TX_STATE] = STATE_WAIT_INPUT;
                    continue;
                }
                short scriptRemaining = Biginteger.getLSB(ctx, TX_SCRIPT_REMAINING,(short)4); 
                short dataAvailable = (ctx2[REMAINING] > scriptRemaining ? scriptRemaining : ctx2[REMAINING]);
                if (dataAvailable == 0) {
                    return RESULT_MORE;
                }
                consumeTransaction(buffer, dataAvailable);
                Biginteger.setByte(ctx, TX_TMP_BUFFER, (short)4, (byte)dataAvailable);
                Biginteger.subtract(ctx, TX_SCRIPT_REMAINING, ctx, TX_TMP_BUFFER, (short)4);
                // at this point the program loop until either the script or the buffer is consumed
            }
            if (ctx[TX_STATE] == STATE_HASHING_INPUT_DONE) {
                if (ctx2[REMAINING] < (short)1) {
                    // No more data to read, ok
                    return RESULT_MORE;
                }
                // Number of outputs
                if (!parseVarint(buffer, ctx, TX_REMAINING_O)) {
                    return RESULT_ERROR;
                }
                ctx[TX_STATE] = STATE_WAIT_OUTPUT;
            }
            if (ctx[TX_STATE] == STATE_WAIT_OUTPUT) {
                if (Biginteger.equalZero(ctx, TX_REMAINING_O,(short)4)) {
                    // No more outputs to hash, move forward
                    ctx[TX_STATE] = STATE_HASHING_OUTPUT_DONE;
                    continue;
                }
                if (ctx2[REMAINING] < (short)1) {
                    // No more data to read, ok
                    return RESULT_MORE;
                }
                // Amount
                if (ctx2[REMAINING] < (short)8) {
                    return RESULT_ERROR;
                }
                Biginteger.swap(buffer, ctx2[CURRENT], ctx, TX_TMP_BUFFER, (short)8);
                Biginteger.add_carry(ctx, TX_AMOUNT, ctx, TX_TMP_BUFFER, (short)8);
                consumeTransaction(buffer, (short)8);
                // Read the script length
                if (!parseVarint(buffer, ctx, TX_SCRIPT_REMAINING)) {
                    return RESULT_ERROR;
                }
                ctx[TX_STATE] = STATE_HASHING_OUTPUT_SCRIPT;
            }
            if (ctx[TX_STATE] == STATE_HASHING_OUTPUT_SCRIPT) {
                if (ctx2[REMAINING] < (short)1) {
                    // No more data to read, ok
                    return RESULT_MORE;
                }
                if (Biginteger.equalZero(ctx,TX_SCRIPT_REMAINING, (short)4)) {
                    // Move to next output
                    Biginteger.subtract1_carry(ctx, TX_REMAINING_O, (short)4);
                    Biginteger.add1_carry(ctx, TX_CURRENT_O, (short)4);
                    ctx[TX_STATE] = STATE_WAIT_OUTPUT;
                    continue;
                }
                short scriptRemaining = Biginteger.getLSB(ctx, TX_SCRIPT_REMAINING,(short)4);
                short dataAvailable = (ctx2[REMAINING] > scriptRemaining ? scriptRemaining : ctx2[REMAINING]);
                if (dataAvailable == 0) {
                    return RESULT_MORE;
                }
                consumeTransaction(buffer, dataAvailable);
                Biginteger.setByte(ctx, TX_TMP_BUFFER, (short)4, (byte)dataAvailable);
                Biginteger.subtract(ctx, TX_SCRIPT_REMAINING, ctx, TX_TMP_BUFFER,(short)4);
            }
            if (ctx[TX_STATE] == STATE_HASHING_OUTPUT_DONE) {
                if (ctx2[REMAINING] < (short)1) {
                    // No more data to read, ok
                    return RESULT_MORE;
                }
                // Locktime
                if (ctx2[REMAINING] < (short)4) {
                    return RESULT_ERROR;
                }
                consumeTransaction(buffer, (short)4);
                // sighash
                if (ctx2[REMAINING] < (short)1) {
                    // No more data to read, ok
                    return RESULT_MORE;
                }
                if (ctx2[REMAINING] < (short)4) {
                    return RESULT_ERROR;
                }
                consumeTransaction(buffer, (short)4);
                ctx[TX_STATE] = STATE_PARSED;
                return RESULT_FINISHED;
            }
        }
    }
    
    /*
    * Parse a list outputs.
    * An output consists of: output= [amount(8b) + script_size(varint) + script]
    */
    public static byte parseOutputs(byte buffer[], short offset, short remaining, short nbOutputs) {
        ctx2[CURRENT] = offset;
        ctx2[REMAINING] = remaining;
        for (;;) {
            if (ctx[TX_STATE] == STATE_NONE) {
                // set number of outputs
                ctx2[NBOUTPUTS]=nbOutputs;
                ctx[TX_STATE] = STATE_WAIT_OUTPUT;     
            }
            if (ctx[TX_STATE] == STATE_WAIT_OUTPUT) {
                if (ctx2[NBOUTPUTS]==0) {
                    // No more outputs to hash, move forward
                    ctx[TX_STATE] = STATE_PARSED_OUTPUTS; // todo: special state?
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
                Biginteger.swap(buffer, ctx2[CURRENT], ctx, TX_TMP_BUFFER, (short)8);
                Biginteger.add_carry(ctx, TX_AMOUNT, ctx, TX_TMP_BUFFER, (short)8);
                consumeTransaction(buffer, (short)8);
                // Read the script length
                if (!parseVarint(buffer, ctx, TX_SCRIPT_REMAINING)) {
                    return RESULT_ERROR;
                }
                ctx[TX_STATE] = STATE_HASHING_OUTPUT_SCRIPT;
            } 
            if (ctx[TX_STATE] == STATE_HASHING_OUTPUT_SCRIPT) {
                if (ctx2[REMAINING] < (short)1) {
                    return RESULT_MORE; // No more data to read, ok
                }
                if (Biginteger.equalZero(ctx,TX_SCRIPT_REMAINING, (short)4)) {
                    // Move to next output
                    ctx2[NBOUTPUTS]=(short)(ctx2[NBOUTPUTS]-1);
                    ctx[TX_STATE] = STATE_WAIT_OUTPUT;
                    continue;
                }
                short scriptRemaining = Biginteger.getLSB(ctx, TX_SCRIPT_REMAINING,(short)4);
                short dataAvailable = (ctx2[REMAINING] > scriptRemaining ? scriptRemaining : ctx2[REMAINING]);
                if (dataAvailable == 0) {
                    return RESULT_MORE;
                }
                consumeTransaction(buffer, dataAvailable);
                Biginteger.setByte(ctx, TX_TMP_BUFFER, (short)4, (byte)dataAvailable);
                Biginteger.subtract(ctx, TX_SCRIPT_REMAINING, ctx, TX_TMP_BUFFER,(short)4);
                // at this point the program loop until either the script or the buffer is consumed
            } 
        }//endfor
    }
    
    /*
    * a segwith tx preimage consists of:
    * preImage= [nVersion(4b) + hasPrevouts(32b) + hashSequence(32b) + outpoint(36b) + scriptCode(varInt)
    *                 + amount(8b) + nsequence(4b) + hashOutputs(32b) + nLocktime(4b) + nHashType(4b)]
    */
    public static byte parseSegwitTransaction(byte buffer[], short offset, short remaining) {
        ctx2[CURRENT] = offset;
        ctx2[REMAINING] = remaining;
        for (;;) {
            if (ctx[TX_STATE] == STATE_NONE) {
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
                
                // Read the script length
                if (!parseVarint(buffer, ctx, TX_SCRIPT_REMAINING)) {
                    return RESULT_ERROR;
                }
                ctx[TX_STATE] = STATE_HASHING_INPUT_SCRIPT;
                
                if (ctx2[REMAINING] < (short)1) {
                    return RESULT_MORE; // No more data to read, ok
                }
            }
            if (ctx[TX_STATE] == STATE_HASHING_INPUT_SCRIPT) {
                if (ctx2[REMAINING] < (short)1) {
                    return RESULT_MORE; // No more data to read, ok
                }
                // if script size is zero or script is already consumed 
                if (Biginteger.equalZero(ctx,TX_SCRIPT_REMAINING,(short)4)) {
                    ctx[TX_STATE] = STATE_HASHING_OUTPUT_DONE;
                    continue;
                }
                short scriptRemaining = Biginteger.getLSB(ctx, TX_SCRIPT_REMAINING,(short)4); 
                short dataAvailable = (ctx2[REMAINING] > scriptRemaining ? scriptRemaining : ctx2[REMAINING]);
                if (dataAvailable == 0) {
                    return RESULT_MORE;
                }
                consumeTransaction(buffer, dataAvailable);
                Biginteger.setByte(ctx, TX_TMP_BUFFER, (short)4, (byte)dataAvailable);
                Biginteger.subtract(ctx, TX_SCRIPT_REMAINING, ctx, TX_TMP_BUFFER, (short)4);
                // at this point the program loop until either the script or the buffer is consumed
            }
            if (ctx[TX_STATE] == STATE_HASHING_OUTPUT_DONE) {    
                if (ctx2[REMAINING] < (short)1) {
                    return RESULT_MORE; // No more data to read, ok
                }
                // amount
                if (ctx2[REMAINING] < (short)8) {
                    return RESULT_ERROR;
                }
                Biginteger.swap(buffer, ctx2[CURRENT], ctx, TX_TMP_BUFFER, (short)8);
                Biginteger.add_carry(ctx, TX_AMOUNT, ctx, TX_TMP_BUFFER, (short)8);
                consumeTransaction(buffer, (short)8);
                // Sequence
                if (ctx2[REMAINING] < (short)4) {
                    return RESULT_ERROR;
                }
                consumeTransaction(buffer, (short)4);
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
                ctx[TX_STATE] = STATE_PARSED;
                return RESULT_FINISHED;
            }        
        }// end for
    }
    
    protected static byte[] ctx;
    protected static short[] ctx2;
    public static MessageDigest digestFull;
    
    private static final byte CURRENT = (byte)0;
    private static final byte REMAINING = (byte)1;
    private static final byte NBOUTPUTS = (byte)2;
    
    
    public static final byte STATE_NONE = (byte)0x00;
    public static final byte STATE_WAIT_INPUT = (byte)0x01;
    public static final byte STATE_HASHING_INPUT_SCRIPT = (byte)0x02;
    public static final byte STATE_HASHING_INPUT_DONE = (byte)0x03;
    public static final byte STATE_WAIT_OUTPUT = (byte)0x04;
    public static final byte STATE_HASHING_OUTPUT_SCRIPT = (byte)0x05;
    public static final byte STATE_HASHING_OUTPUT_DONE = (byte)0x06;
    public static final byte STATE_PARSED = (byte)0x07;
    public static final byte STATE_PARSED_OUTPUTS = (byte)0x08;
    
    
    public static final byte RESULT_FINISHED = (byte)0x13;
    public static final byte RESULT_ERROR = (byte)0x79;
    public static final byte RESULT_MORE = (byte)0x00;
        
    // Transaction context
    protected static final byte SIZEOF_U32 = 4;
    protected static final byte SIZEOF_U8 = 1;
    protected static final byte SIZEOF_AMOUNT = 8;
    
    protected static final byte INACTIVE = (byte)0x00;
    protected static final byte ACTIVE = (byte)0x01;
    
    // context data
    //protected static final short TX_HASH_OPTION = (short)0;
    protected static final short TX_REMAINING_I = (short)0;//(short)(TX_HASH_OPTION + SIZEOF_U8);
    protected static final short TX_CURRENT_I = (short)(TX_REMAINING_I + SIZEOF_U32);
    protected static final short TX_REMAINING_O = (short)(TX_CURRENT_I + SIZEOF_U32);
    protected static final short TX_CURRENT_O = (short)(TX_REMAINING_O + SIZEOF_U32);
    protected static final short TX_SCRIPT_REMAINING = (short)(TX_CURRENT_O + SIZEOF_U32);
    protected static final short TX_STATE = (short)(TX_SCRIPT_REMAINING + SIZEOF_U32);
    protected static final short TX_AMOUNT = (short)(TX_STATE + SIZEOF_U8);
    protected static final short TX_SCRIPT_ACTIVE = (short)(TX_AMOUNT + SIZEOF_AMOUNT);
    protected static final short TX_SCRIPT_COORD = (short)(TX_SCRIPT_ACTIVE + SIZEOF_U8);
    protected static final short TX_TMP_BUFFER = (short)(TX_SCRIPT_COORD + SIZEOF_U32);
    protected static final short TX_CONTEXT_SIZE = (short)(TX_TMP_BUFFER + SIZEOF_AMOUNT);  
    
}
