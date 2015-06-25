/*
*******************************************************************************    
*   BTChip Bitcoin Hardware Wallet Java Card implementation
*   (c) 2013 BTChip - 1BTChip7VfTnrPra5jqci7ejnMguuHogTn
*   
*   Changes by Toporin for the Bitcoin SatoChip Hardware Wallet
*   Sources available on https://github.com/Toporin
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
 * Bitcoin transaction parsing
 * @author BTChip
 *
 */
public class Transaction {
    
    public static void init() {
        h = JCSystem.makeTransientShortArray((short)2, JCSystem.CLEAR_ON_DESELECT);
        ctx = JCSystem.makeTransientByteArray(TX_CONTEXT_SIZE, JCSystem.CLEAR_ON_DESELECT);
        digestFull = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
    }
    
    private static void consumeTransaction(byte buffer[], short length) {
        digestFull.update(buffer, h[CURRENT], length);
        h[REMAINING] -= length;
        h[CURRENT] += length;
    }
    
    private static boolean parseVarint(byte[] buffer, byte[] target, short targetOffset) {
        if (h[REMAINING] < (short)1) {
            return false;
        }
        short firstByte = (short)(buffer[h[CURRENT]] & 0xff);
        if (firstByte < (short)0xfd) {
            Biginteger.setByte(target, targetOffset, (short)4, (byte)firstByte);
            consumeTransaction(buffer, (short)1);            
        }
        else
        if (firstByte == (short)0xfd) {
            consumeTransaction(buffer, (short)1);
            if (h[REMAINING] < (short)2) {
                return false;
            }
            target[targetOffset]=0x00;
            target[(short)(targetOffset+1)]=0x00;
            target[(short)(targetOffset+2)]=buffer[(short)(h[CURRENT] + 1)];
            target[(short)(targetOffset+3)]=buffer[h[CURRENT]];
            consumeTransaction(buffer, (short)2);
        }
        else
        if (firstByte == (short)0xfe) {
            consumeTransaction(buffer, (short)1);
            if (h[REMAINING] < (short)4) { 
                return false;
            }
            target[targetOffset]=buffer[(short)(h[CURRENT] + 3)];
            target[(short)(targetOffset+1)]=buffer[(short)(h[CURRENT] + 2)];
            target[(short)(targetOffset+2)]=buffer[(short)(h[CURRENT] + 1)];
            target[(short)(targetOffset+3)]=buffer[h[CURRENT]];
            consumeTransaction(buffer, (short)4);
        }
        else {
            return false;
        }
        return true;
    }
    
    public static void resetTransaction(){
    		ctx[TX_B_TRANSACTION_STATE] = STATE_NONE;          
            Biginteger.setZero(ctx, TX_I_REMAINING_I, (short)4);
            Biginteger.setZero(ctx, TX_I_REMAINING_O, (short)4);
            Biginteger.setZero(ctx, TX_I_CURRENT_I, (short)4);
            Biginteger.setZero(ctx, TX_I_CURRENT_O, (short)4);
            Biginteger.setZero(ctx, TX_I_SCRIPT_REMAINING, (short)4);
            Biginteger.setZero(ctx, TX_A_TRANSACTION_AMOUNT, (short)8);
            Biginteger.setZero(ctx, TX_I_SCRIPT_COORD, (short)4);
            Biginteger.setZero(ctx, TX_TMP_BUFFER, (short)8);
            ctx[TX_I_SCRIPT_ACTIVE] = INACTIVE;
            digestFull.reset();
            return;
    }
       
    public static byte parseTransaction(byte buffer[], short offset, short remaining) {
        h[CURRENT] = offset;
        h[REMAINING] = remaining;
        for (;;) {
            if (ctx[TX_B_TRANSACTION_STATE] == STATE_NONE) {
                
                // Parse the beginning of the transaction
                // Version
                if (h[REMAINING] < (short)4) {
                    return RESULT_ERROR;
                }
                consumeTransaction(buffer, (short)4);
                // Number of inputs
                if (!parseVarint(buffer, ctx, TX_I_REMAINING_I)) {
                    return RESULT_ERROR;
                }
                ctx[TX_B_TRANSACTION_STATE] = STATE_DEFINED_WAIT_INPUT;
            }
            if (ctx[TX_B_TRANSACTION_STATE] == STATE_DEFINED_WAIT_INPUT) {
                if (Biginteger.equalZero(ctx, TX_I_REMAINING_I,(short)4)) {	
            		if (ctx[TX_I_SCRIPT_ACTIVE]== INACTIVE){
                		// there should be exactly one input script active at this point
                		return RESULT_ERROR;
                	}
                	// No more inputs to hash, move forward
                    ctx[TX_B_TRANSACTION_STATE] = STATE_INPUT_HASHING_DONE;
                    continue;
                }
                if (h[REMAINING] < (short)1) {
                    // No more data to read, ok
                    return RESULT_MORE;
                }
                // Proceed with the next input
                if (h[REMAINING] < (short)36) { // prevout : 32 hash + 4 index
                    return RESULT_ERROR;
                }
                consumeTransaction(buffer, (short)36);
                // Read the script length
                if (!parseVarint(buffer, ctx, TX_I_SCRIPT_REMAINING)) {
                    return RESULT_ERROR;
                }
                else if (!Biginteger.equalZero(ctx,TX_I_SCRIPT_REMAINING, (short)4)){
                	// check if a script was already present
                	if (ctx[TX_I_SCRIPT_ACTIVE]== INACTIVE){
                		ctx[TX_I_SCRIPT_ACTIVE]= ACTIVE;
                        Util.arrayCopyNonAtomic(ctx, TX_I_CURRENT_I, ctx, TX_I_SCRIPT_COORD, SIZEOF_U32); 
                	}
                	else { // there should be only one input script active
                		return RESULT_ERROR;
                	}
                }
                ctx[TX_B_TRANSACTION_STATE] = STATE_INPUT_HASHING_IN_PROGRESS_INPUT_SCRIPT;                
            }
            if (ctx[TX_B_TRANSACTION_STATE] == STATE_INPUT_HASHING_IN_PROGRESS_INPUT_SCRIPT) {
                if (h[REMAINING] < (short)1) {
                    // No more data to read, ok
                    return RESULT_MORE;
                }
                // if script size is zero or script is already consumed 
                if (Biginteger.equalZero(ctx,TX_I_SCRIPT_REMAINING,(short)4)) {
                    // Sequence
                    if (h[REMAINING] < (short)4) {
                        return RESULT_ERROR;
                    }
                    // TODO : enforce sequence
                    consumeTransaction(buffer, (short)4);
                    // Move to next input
                    Biginteger.subtract1_carry(ctx, TX_I_REMAINING_I,(short)4);
                    Biginteger.add1_carry(ctx, TX_I_CURRENT_I, (short)4);
                    ctx[TX_B_TRANSACTION_STATE] = STATE_DEFINED_WAIT_INPUT;
                    continue;
                }
                short scriptRemaining = Biginteger.getLSB(ctx, TX_I_SCRIPT_REMAINING,(short)4); 
                short dataAvailable = (h[REMAINING] > scriptRemaining ? scriptRemaining : h[REMAINING]);
                if (dataAvailable == 0) {
                    return RESULT_MORE;
                }
                consumeTransaction(buffer, dataAvailable);
                Biginteger.setByte(ctx, TX_TMP_BUFFER, (short)4, (byte)dataAvailable);
                Biginteger.subtract(ctx, TX_I_SCRIPT_REMAINING, ctx, TX_TMP_BUFFER, (short)4);
                // at this point the program loop until either the script or the buffer is consumed
            }
            if (ctx[TX_B_TRANSACTION_STATE] == STATE_INPUT_HASHING_DONE) {
                if (h[REMAINING] < (short)1) {
                    // No more data to read, ok
                    return RESULT_MORE;
                }
                // Number of outputs
                if (!parseVarint(buffer, ctx, TX_I_REMAINING_O)) {
                    return RESULT_ERROR;
                }
                ctx[TX_B_TRANSACTION_STATE] = STATE_DEFINED_WAIT_OUTPUT;
            }
            if (ctx[TX_B_TRANSACTION_STATE] == STATE_DEFINED_WAIT_OUTPUT) {
            	if (Biginteger.equalZero(ctx, TX_I_REMAINING_O,(short)4)) {
                    // No more outputs to hash, move forward
                    ctx[TX_B_TRANSACTION_STATE] = STATE_OUTPUT_HASHING_DONE;
                    continue;
                }
                if (h[REMAINING] < (short)1) {
                    // No more data to read, ok
                    return RESULT_MORE;
                }
                // Amount
                if (h[REMAINING] < (short)8) {
                    return RESULT_ERROR;
                }
                Biginteger.swap(buffer, h[CURRENT], ctx, TX_TMP_BUFFER, (short)8);
                Biginteger.add_carry(ctx, TX_A_TRANSACTION_AMOUNT, ctx, TX_TMP_BUFFER, (short)8);
                consumeTransaction(buffer, (short)8);
                // Read the script length
                if (!parseVarint(buffer, ctx, TX_I_SCRIPT_REMAINING)) {
                    return RESULT_ERROR;
                }
                ctx[TX_B_TRANSACTION_STATE] = STATE_OUTPUT_HASHING_IN_PROGRESS_OUTPUT_SCRIPT;
            }
            if (ctx[TX_B_TRANSACTION_STATE] == STATE_OUTPUT_HASHING_IN_PROGRESS_OUTPUT_SCRIPT) {
                if (h[REMAINING] < (short)1) {
                    // No more data to read, ok
                    return RESULT_MORE;
                }
                if (Biginteger.equalZero(ctx,TX_I_SCRIPT_REMAINING, (short)4)) {
                    // Move to next output
                    Biginteger.subtract1_carry(ctx, TX_I_REMAINING_O, (short)4);
                    Biginteger.add1_carry(ctx, TX_I_CURRENT_O, (short)4);
                    ctx[TX_B_TRANSACTION_STATE] = STATE_DEFINED_WAIT_OUTPUT;
                    continue;
                }
                short scriptRemaining = Biginteger.getLSB(ctx, TX_I_SCRIPT_REMAINING,(short)4);
                short dataAvailable = (h[REMAINING] > scriptRemaining ? scriptRemaining : h[REMAINING]);
                if (dataAvailable == 0) {
                    return RESULT_MORE;
                }
                consumeTransaction(buffer, dataAvailable);
                Biginteger.setByte(ctx, TX_TMP_BUFFER, (short)4, (byte)dataAvailable);
                Biginteger.subtract(ctx, TX_I_SCRIPT_REMAINING, ctx, TX_TMP_BUFFER,(short)4);
            }
            if (ctx[TX_B_TRANSACTION_STATE] == STATE_OUTPUT_HASHING_DONE) {
                if (h[REMAINING] < (short)1) {
                    // No more data to read, ok
                    return RESULT_MORE;
                }
                // Locktime
                if (h[REMAINING] < (short)4) {
                    return RESULT_ERROR;
                }
                consumeTransaction(buffer, (short)4);
                // sighash
                if (h[REMAINING] < (short)1) {
                    // No more data to read, ok
                    return RESULT_MORE;
                }
                if (h[REMAINING] < (short)4) {
                    return RESULT_ERROR;
                }
                consumeTransaction(buffer, (short)4);
                ctx[TX_B_TRANSACTION_STATE] = STATE_PARSED;
                return RESULT_FINISHED;
            }
        }
    }
    
    private static short[] h;
    protected static byte[] ctx;
    public static MessageDigest digestFull;
    
    private static final byte CURRENT = (byte)0;
    private static final byte REMAINING = (byte)1;
    
    public static final byte STATE_NONE = (byte)0x00;
    public static final byte STATE_DEFINED_WAIT_INPUT = (byte)0x01;
    public static final byte STATE_INPUT_HASHING_IN_PROGRESS_INPUT_SCRIPT = (byte)0x02;
    public static final byte STATE_INPUT_HASHING_DONE = (byte)0x03;
    public static final byte STATE_DEFINED_WAIT_OUTPUT = (byte)0x04;
    public static final byte STATE_OUTPUT_HASHING_IN_PROGRESS_OUTPUT_SCRIPT = (byte)0x05;
    public static final byte STATE_OUTPUT_HASHING_DONE = (byte)0x06;
    public static final byte STATE_PARSED = (byte)0x07;
    
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
    protected static final short TX_B_HASH_OPTION = (short)0;
    protected static final short TX_I_REMAINING_I = (short)(TX_B_HASH_OPTION + SIZEOF_U8);
    protected static final short TX_I_CURRENT_I = (short)(TX_I_REMAINING_I + SIZEOF_U32);
    protected static final short TX_I_REMAINING_O = (short)(TX_I_CURRENT_I + SIZEOF_U32);
    protected static final short TX_I_CURRENT_O = (short)(TX_I_REMAINING_O + SIZEOF_U32);
    protected static final short TX_I_SCRIPT_REMAINING = (short)(TX_I_CURRENT_O + SIZEOF_U32);
    protected static final short TX_B_TRANSACTION_STATE = (short)(TX_I_SCRIPT_REMAINING + SIZEOF_U32);
    protected static final short TX_A_TRANSACTION_AMOUNT = (short)(TX_B_TRANSACTION_STATE + SIZEOF_U8);
    protected static final short TX_I_SCRIPT_ACTIVE = (short)(TX_A_TRANSACTION_AMOUNT + SIZEOF_AMOUNT);
    protected static final short TX_I_SCRIPT_COORD = (short)(TX_I_SCRIPT_ACTIVE + SIZEOF_U8);
    protected static final short TX_TMP_BUFFER = (short)(TX_I_SCRIPT_COORD + SIZEOF_U32);
    protected static final short TX_CONTEXT_SIZE = (short)(TX_TMP_BUFFER + SIZEOF_AMOUNT);  
    
}
