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
import javacard.security.MessageDigest;

// very limited Hmac-SHA160 implementation
public class HmacSha160 {

	private static MessageDigest sha160;
	public static final short BLOCKSIZE=64; // 64 bytes 
	public static final short HASHSIZE=20;
	public static final short MAXMSGSIZE=192; 
	private static final short SW_UNSUPPORTED_KEYSIZE = (short) 0x9c0E;
	private static final short SW_UNSUPPORTED_MSGSIZE = (short) 0x9c0F;
	private static byte[] data;
	
	
	public static void init(byte[] tmp){
		sha160= MessageDigest.getInstance(MessageDigest.ALG_SHA, false);
		data= tmp;
	}
	
	public static short computeHmacSha160(
			byte[] key, short key_offset, short key_length, 
			byte[] message, short message_offset, short message_length,
			byte[] mac, short mac_offset){
		
		if (key_length>BLOCKSIZE || key_length<0){
			ISOException.throwIt(SW_UNSUPPORTED_KEYSIZE); // don't accept keys bigger than block size 
		}
		if (message_length>MAXMSGSIZE || message_length<0){
			ISOException.throwIt(SW_UNSUPPORTED_MSGSIZE); 
		}
		
		// compute inner hash
		for (short i=0; i<key_length; i++){
			data[i]= (byte) (key[(short)(key_offset+i)] ^ (0x36));
		}
		for (short i=key_length; i<BLOCKSIZE; i++){
			data[i]= (byte) 0x36;
		}
		for (short i=0; i<message_length; i++){
			data[(short)(BLOCKSIZE+i)]= message[(short)(message_offset+i)];
		}
		sha160.reset();
		sha160.doFinal(data, (short)0, (short)(BLOCKSIZE+message_length), data, BLOCKSIZE); // copy hash result to data buffer!
		
		// compute outer hash
		for (short i=0; i<key_length; i++){
			data[i]= (byte) (key[(short)(key_offset+i)] ^ (0x5c));
		}
		for (short i=key_length; i<BLOCKSIZE; i++){
			data[i]= (byte) 0x5c;
		}
		// previous hash already copied to correct offset in data
		sha160.reset();
		sha160.doFinal(data, (short)0, (short)(BLOCKSIZE+HASHSIZE), mac, mac_offset);
		return HASHSIZE;
	}	
	
}
