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
 *******************************************************************************   
 */    

package org.satochip.applet;

import javacard.framework.ISOException;
import javacard.framework.JCSystem;

// very limited Hmac-SHA512 implementation
public class HmacSha512 {

	private Sha2 sha512;
	public static final short block_size=128; // 128 bytes 
	public static final short hash_size=64;
	private static final short SW_UNSUPPORTED_KEYSIZE = (short) 0x9c0E;
	private static final short SW_UNSUPPORTED_MSGSIZE = (short) 0x9c0F;
	private byte[] data;
	
	
	public HmacSha512(){
		this.sha512= new Sha2(Sha2.SHA_512);
		this.data= JCSystem.makeTransientByteArray((short)(block_size+hash_size), JCSystem.CLEAR_ON_DESELECT);
		//this.data= new byte[(short)(block_size+hash_size)];
	}
	
	public void computeHmacSha512(byte[] key, short key_offset, short key_length, 
			byte[] message, short message_offset, short message_length,
			byte[] mac, short mac_offset){
		
		// compute inner hash
		if (key_length>block_size || key_length<0){
			ISOException.throwIt(SW_UNSUPPORTED_KEYSIZE); // don't accept keys bigger than block size 
		}
		if (message_length>hash_size || message_length<0){
			ISOException.throwIt(SW_UNSUPPORTED_MSGSIZE); // don't accept messsage bigger than block size (should be sufficient for BIP32)
		}
		for (short i=0; i<key_length; i++){
			data[i]= (byte) (key[(short)(key_offset+i)] ^ (0x36));
			//key_block[i]= (byte) (key[(short)(key_offset+i)] ^ (0x36));
		}
		for (short i=key_length; i<block_size; i++){
			data[i]= (byte) 0x36;
			//key_block[i]= (byte) 0x36;
		}
		for (short i=0; i<message_length; i++){
			data[(short)(block_size+i)]= message[(short)(message_offset+i)];
		}
		sha512.reset();
		//sha512.update(key_block, (short)0, block_size);
		//sha512.doFinal(message, message_offset, message_length, mac, (short)0);
		sha512.doFinal(data, (short)0, (short)(block_size+message_length), data, block_size); // copy hash result to data buffer!
		
		// compute outer hash
		for (short i=0; i<key_length; i++){
			data[i]= (byte) (key[(short)(key_offset+i)] ^ (0x5c));
			//key_block[i]= (byte) (key[(short)(key_offset+i)] ^ (0x5c));
		}
		for (short i=key_length; i<block_size; i++){
			data[i]= (byte) 0x5c;
			//key_block[i]= (byte) 0x5c;
		}
		// previous hash already copied to correct offset in data
		sha512.reset();
		sha512.doFinal(data, (short)0, (short)(block_size+hash_size), mac, mac_offset);
		return;
	}	
	
}
