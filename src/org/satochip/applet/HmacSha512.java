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
import javacard.framework.JCSystem;
import javacard.framework.Util;

// very limited Hmac-SHA512 implementation
public class HmacSha512 {

	public static final short BLOCKSIZE=128; // 128 bytes 
	public static final short HASHSIZE=64;
	private static final short SW_UNSUPPORTED_KEYSIZE = (short) 0x9c0E;
	private static final short SW_UNSUPPORTED_MSGSIZE = (short) 0x9c0F;
	private static byte[] data;
	
	
	public static void init(byte[] tmp){
		data= tmp;
	}
	
	public static short computeHmacSha512(byte[] key, short key_offset, short key_length, 
			byte[] message, short message_offset, short message_length,
			byte[] mac, short mac_offset){
		
		if (key_length>BLOCKSIZE || key_length<0){
			ISOException.throwIt(SW_UNSUPPORTED_KEYSIZE); // don't accept keys bigger than block size 
		}
		if (message_length>HASHSIZE || message_length<0){
			ISOException.throwIt(SW_UNSUPPORTED_MSGSIZE); // don't accept messsage bigger than block size (should be sufficient for BIP32)
		}
		
		// compute inner hash
		for (short i=0; i<key_length; i++){
			data[i]= (byte) (key[(short)(key_offset+i)] ^ (0x36));
		}
		Util.arrayFillNonAtomic(data, key_length, (short)(BLOCKSIZE-key_length), (byte)0x36);		
		Util.arrayCopyNonAtomic(message, message_offset, data, BLOCKSIZE, message_length);
		//Sha512.reset();
		//Sha512.doFinal(data, (short)0, (short)(BLOCKSIZE+message_length), data, BLOCKSIZE); // copy hash result to data buffer!
		Sha512.resetUpdateDoFinal(data, (short)0, (short)(BLOCKSIZE+message_length), data, BLOCKSIZE); // copy hash result to data buffer!
		
		// compute outer hash
		for (short i=0; i<key_length; i++){
			data[i]= (byte) (key[(short)(key_offset+i)] ^ (0x5c));
		}
		Util.arrayFillNonAtomic(data, key_length, (short)(BLOCKSIZE-key_length), (byte)0x5c);
		// previous hash already copied to correct offset in data
		//Sha512.reset();
		//Sha512.doFinal(data, (short)0, (short)(BLOCKSIZE+HASHSIZE), mac, mac_offset);
		Sha512.resetUpdateDoFinal(data, (short)0, (short)(BLOCKSIZE+HASHSIZE), mac, mac_offset);
		
		return HASHSIZE;
	}	
	
}
