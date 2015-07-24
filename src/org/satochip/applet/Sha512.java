package org.satochip.applet;

import javacard.framework.JCSystem;
import javacard.framework.Util;
public class Sha512 {

    public static final short[] H_INIT_SHORT={
        (short) 0x6a09, (short) 0xe667, (short) 0xf3bc, (short) 0xc908,
        (short) 0xbb67, (short) 0xae85, (short) 0x84ca, (short) 0xa73b,
        (short) 0x3c6e, (short) 0xf372, (short) 0xfe94, (short) 0xf82b,
        (short) 0xa54f, (short) 0xf53a, (short) 0x5f1d, (short) 0x36f1,
        (short) 0x510e, (short) 0x527f, (short) 0xade6, (short) 0x82d1,
        (short) 0x9b05, (short) 0x688c, (short) 0x2b3e, (short) 0x6c1f,
        (short) 0x1f83, (short) 0xd9ab, (short) 0xfb41, (short) 0xbd6b,
        (short) 0x5be0, (short) 0xcd19, (short) 0x137e, (short) 0x2179
    };

    public static final short[] K_SHORT={
	  (short) 0x428a,(short) 0x2f98,(short) 0xd728,(short) 0xae22,
	  (short) 0x7137,(short) 0x4491,(short) 0x23ef,(short) 0x65cd,
	  (short) 0xb5c0,(short) 0xfbcf,(short) 0xec4d,(short) 0x3b2f,
	  (short) 0xe9b5,(short) 0xdba5,(short) 0x8189,(short) 0xdbbc,
	  (short) 0x3956,(short) 0xc25b,(short) 0xf348,(short) 0xb538,
	  (short) 0x59f1,(short) 0x11f1,(short) 0xb605,(short) 0xd019,
	  (short) 0x923f,(short) 0x82a4,(short) 0xaf19,(short) 0x4f9b,
	  (short) 0xab1c,(short) 0x5ed5,(short) 0xda6d,(short) 0x8118,
	  (short) 0xd807,(short) 0xaa98,(short) 0xa303,(short) 0x0242,
	  (short) 0x1283,(short) 0x5b01,(short) 0x4570,(short) 0x6fbe,
	  (short) 0x2431,(short) 0x85be,(short) 0x4ee4,(short) 0xb28c,
	  (short) 0x550c,(short) 0x7dc3,(short) 0xd5ff,(short) 0xb4e2,
	  (short) 0x72be,(short) 0x5d74,(short) 0xf27b,(short) 0x896f,
	  (short) 0x80de,(short) 0xb1fe,(short) 0x3b16,(short) 0x96b1,
	  (short) 0x9bdc,(short) 0x06a7,(short) 0x25c7,(short) 0x1235,
	  (short) 0xc19b,(short) 0xf174,(short) 0xcf69,(short) 0x2694,
	  (short) 0xe49b,(short) 0x69c1,(short) 0x9ef1,(short) 0x4ad2,
	  (short) 0xefbe,(short) 0x4786,(short) 0x384f,(short) 0x25e3,
	  (short) 0x0fc1,(short) 0x9dc6,(short) 0x8b8c,(short) 0xd5b5,
	  (short) 0x240c,(short) 0xa1cc,(short) 0x77ac,(short) 0x9c65,
	  (short) 0x2de9,(short) 0x2c6f,(short) 0x592b,(short) 0x0275,
	  (short) 0x4a74,(short) 0x84aa,(short) 0x6ea6,(short) 0xe483,
	  (short) 0x5cb0,(short) 0xa9dc,(short) 0xbd41,(short) 0xfbd4,
	  (short) 0x76f9,(short) 0x88da,(short) 0x8311,(short) 0x53b5,
	  (short) 0x983e,(short) 0x5152,(short) 0xee66,(short) 0xdfab,
	  (short) 0xa831,(short) 0xc66d,(short) 0x2db4,(short) 0x3210,
	  (short) 0xb003,(short) 0x27c8,(short) 0x98fb,(short) 0x213f,
	  (short) 0xbf59,(short) 0x7fc7,(short) 0xbeef,(short) 0x0ee4,
	  (short) 0xc6e0,(short) 0x0bf3,(short) 0x3da8,(short) 0x8fc2,
	  (short) 0xd5a7,(short) 0x9147,(short) 0x930a,(short) 0xa725,
	  (short) 0x06ca,(short) 0x6351,(short) 0xe003,(short) 0x826f,
	  (short) 0x1429,(short) 0x2967,(short) 0x0a0e,(short) 0x6e70,
	  (short) 0x27b7,(short) 0x0a85,(short) 0x46d2,(short) 0x2ffc,
	  (short) 0x2e1b,(short) 0x2138,(short) 0x5c26,(short) 0xc926,
	  (short) 0x4d2c,(short) 0x6dfc,(short) 0x5ac4,(short) 0x2aed,
	  (short) 0x5338,(short) 0x0d13,(short) 0x9d95,(short) 0xb3df,
	  (short) 0x650a,(short) 0x7354,(short) 0x8baf,(short) 0x63de,
	  (short) 0x766a,(short) 0x0abb,(short) 0x3c77,(short) 0xb2a8,
	  (short) 0x81c2,(short) 0xc92e,(short) 0x47ed,(short) 0xaee6,
	  (short) 0x9272,(short) 0x2c85,(short) 0x1482,(short) 0x353b,
	  (short) 0xa2bf,(short) 0xe8a1,(short) 0x4cf1,(short) 0x0364,
	  (short) 0xa81a,(short) 0x664b,(short) 0xbc42,(short) 0x3001,
	  (short) 0xc24b,(short) 0x8b70,(short) 0xd0f8,(short) 0x9791,
	  (short) 0xc76c,(short) 0x51a3,(short) 0x0654,(short) 0xbe30,
	  (short) 0xd192,(short) 0xe819,(short) 0xd6ef,(short) 0x5218,
	  (short) 0xd699,(short) 0x0624,(short) 0x5565,(short) 0xa910,
	  (short) 0xf40e,(short) 0x3585,(short) 0x5771,(short) 0x202a,
	  (short) 0x106a,(short) 0xa070,(short) 0x32bb,(short) 0xd1b8,
	  (short) 0x19a4,(short) 0xc116,(short) 0xb8d2,(short) 0xd0c8,
	  (short) 0x1e37,(short) 0x6c08,(short) 0x5141,(short) 0xab53,
	  (short) 0x2748,(short) 0x774c,(short) 0xdf8e,(short) 0xeb99,
	  (short) 0x34b0,(short) 0xbcb5,(short) 0xe19b,(short) 0x48a8,
	  (short) 0x391c,(short) 0x0cb3,(short) 0xc5c9,(short) 0x5a63,
	  (short) 0x4ed8,(short) 0xaa4a,(short) 0xe341,(short) 0x8acb,
	  (short) 0x5b9c,(short) 0xca4f,(short) 0x7763,(short) 0xe373,
	  (short) 0x682e,(short) 0x6ff3,(short) 0xd6b2,(short) 0xb8a3,
	  (short) 0x748f,(short) 0x82ee,(short) 0x5def,(short) 0xb2fc,
	  (short) 0x78a5,(short) 0x636f,(short) 0x4317,(short) 0x2f60,
	  (short) 0x84c8,(short) 0x7814,(short) 0xa1f0,(short) 0xab72,
	  (short) 0x8cc7,(short) 0x0208,(short) 0x1a64,(short) 0x39ec,
	  (short) 0x90be,(short) 0xfffa,(short) 0x2363,(short) 0x1e28,
	  (short) 0xa450,(short) 0x6ceb,(short) 0xde82,(short) 0xbde9,
	  (short) 0xbef9,(short) 0xa3f7,(short) 0xb2c6,(short) 0x7915,
	  (short) 0xc671,(short) 0x78f2,(short) 0xe372,(short) 0x532b,
	  (short) 0xca27,(short) 0x3ece,(short) 0xea26,(short) 0x619c,
	  (short) 0xd186,(short) 0xb8c7,(short) 0x21c0,(short) 0xc207,
	  (short) 0xeada,(short) 0x7dd6,(short) 0xcde0,(short) 0xeb1e,
	  (short) 0xf57d,(short) 0x4f7f,(short) 0xee6e,(short) 0xd178,
	  (short) 0x06f0,(short) 0x67aa,(short) 0x7217,(short) 0x6fba,
	  (short) 0x0a63,(short) 0x7dc5,(short) 0xa2c8,(short) 0x98a6,
	  (short) 0x113f,(short) 0x9804,(short) 0xbef9,(short) 0x0dae,
	  (short) 0x1b71,(short) 0x0b35,(short) 0x131c,(short) 0x471b,
	  (short) 0x28db,(short) 0x77f5,(short) 0x2304,(short) 0x7d84,
	  (short) 0x32ca,(short) 0xab7b,(short) 0x40c7,(short) 0x2493,
	  (short) 0x3c9e,(short) 0xbe0a,(short) 0x15c9,(short) 0xbebc,
	  (short) 0x431d,(short) 0x67c4,(short) 0x9c10,(short) 0x0d4c,
	  (short) 0x4cc5,(short) 0xd4be,(short) 0xcb3e,(short) 0x42b6,
	  (short) 0x597f,(short) 0x299c,(short) 0xfc65,(short) 0x7e2a,
	  (short) 0x5fcb,(short) 0x6fab,(short) 0x3ad6,(short) 0xfaec,
	  (short) 0x6c44,(short) 0x198c,(short) 0x4a47,(short) 0x5817
    };

	public static short[] tmp;
	public static final short TMP1=0;
	public static final short TMP2=4;
	public static final short REG1=8;
	public static final short REG2=12;

    public static short[] h_short;
    public static short[] w_short;

    public static short[] hashState;
    public static byte[] buffer;
    public static short bufferOff;
    public static short bufferLeft;

    public static byte[] dataSize;
	public static final short MSGSIZE=0;
	public static final short CHUNKSIZE=4;

    public static void init(){

    	w_short= JCSystem.makeTransientShortArray((short) (64), JCSystem.CLEAR_ON_DESELECT);
    	h_short= JCSystem.makeTransientShortArray((short) (32), JCSystem.CLEAR_ON_DESELECT);
    	tmp= JCSystem.makeTransientShortArray((short) (16), JCSystem.CLEAR_ON_DESELECT);

        hashState= JCSystem.makeTransientShortArray((short) (32), JCSystem.CLEAR_ON_DESELECT);
        buffer= JCSystem.makeTransientByteArray((short) (128), JCSystem.CLEAR_ON_DESELECT);



    }
	public static short resetUpdateDoFinal(byte[] inBuff, short inOffset, short inLength, byte[] outBuff, short outOffset){


		short akku,posy,posx,addx,addy;


		bufferOff=0;
        bufferLeft=128;





		Util.arrayCopyNonAtomic(inBuff, inOffset, buffer, bufferOff, bufferLeft);
		inOffset+=bufferLeft;
		bufferLeft=128;
		bufferOff=0;


		for (short i=0; i<32; i++){
			hashState[i]= H_INIT_SHORT[i];
			h_short[i]=hashState[i];
		}
		CompressionFunction(h_short, (short)0, buffer, (short)0);

		for (short i=0; i<32; i+=4){
			akku = 0; posy = (short)((i)+3); posx = (short)((i)+3); addx=hashState[posx]; addy=h_short[posy]; hashState[posx] = (short)(addx+addy+akku); akku= (short)(( ((addx&addy)|((addx|addy) & ~hashState[posx])) >>15)&1); posy--; posx--; addx=hashState[posx]; addy=h_short[posy]; hashState[posx] = (short)(addx+addy+akku); akku= (short)(( ((addx&addy)|((addx|addy) & ~hashState[posx])) >>15)&1); posy--; posx--; addx=hashState[posx]; addy=h_short[posy]; hashState[posx] = (short)(addx+addy+akku); akku= (short)(( ((addx&addy)|((addx|addy) & ~hashState[posx])) >>15)&1); posy--; posx--; addx=hashState[posx]; addy=h_short[posy]; hashState[posx] = (short)(addx+addy+akku) ;
		}


		short remainingBytes= (short)(inLength-(short)128);
        Util.arrayCopyNonAtomic(inBuff, inOffset, buffer, bufferOff, remainingBytes);
        bufferLeft-=remainingBytes;
        bufferOff+=remainingBytes;




		buffer[bufferOff]=(byte)0x80;
		bufferLeft--;
		bufferOff++;
		Util.arrayFillNonAtomic(buffer, bufferOff, bufferLeft, (byte)0x00);


		buffer[(short)(buffer.length-2)]=(byte)(((short)(8*inLength)>>8)&0xff);
		buffer[(short)(buffer.length-1)]=(byte)((8*inLength) &0xff);


		for (short i=0; i<32; i++){
			h_short[i]=hashState[i];
		}
		CompressionFunction(h_short, (short)0, buffer, (short)0);

		for (short i=0; i<32; i+=4){
			akku = 0; posy = (short)((i)+3); posx = (short)((i)+3); addx=hashState[posx]; addy=h_short[posy]; hashState[posx] = (short)(addx+addy+akku); akku= (short)(( ((addx&addy)|((addx|addy) & ~hashState[posx])) >>15)&1); posy--; posx--; addx=hashState[posx]; addy=h_short[posy]; hashState[posx] = (short)(addx+addy+akku); akku= (short)(( ((addx&addy)|((addx|addy) & ~hashState[posx])) >>15)&1); posy--; posx--; addx=hashState[posx]; addy=h_short[posy]; hashState[posx] = (short)(addx+addy+akku); akku= (short)(( ((addx&addy)|((addx|addy) & ~hashState[posx])) >>15)&1); posy--; posx--; addx=hashState[posx]; addy=h_short[posy]; hashState[posx] = (short)(addx+addy+akku) ;
		}


        for (short i=0; i<32; i++){
            outBuff[outOffset]=(byte)((hashState[i]>>8)&0xff);
            outOffset++;
            outBuff[outOffset]=(byte)(hashState[i]&0xff);
            outOffset++;
        }

        return (short)64;
    }

    public static void CompressionFunction(short[] state, short stateOff, byte[] msgBlock, short msgOff){


		short akku,posy,posx,addx,addy;
		short off1, off2, off3;
		short leftShifts;



    	for (short dstOff=0; dstOff<64; dstOff++){ w_short[dstOff]= Util.getShort(msgBlock, (short)((msgOff)+2*dstOff)); } ;

    	short hOff=0, wOff=0;
		for (short round=0; round<80; round++){



			tmp[REG1]= w_short[wOff]; tmp[(short)(REG1+1)]= w_short[(short)(wOff+1)]; tmp[(short)(REG1+2)]= w_short[(short)(wOff+2)]; tmp[(short)(REG1+3)]= w_short[(short)(wOff+3)]; off1=(short)(((short)(wOff+56))%64); off2=(short)(((short)(wOff+36))%64); off3=(short)(((short)(wOff+4))%64); leftShifts = (short)(16-(short)3); tmp[(short)(TMP1+1)]= (short) (((w_short[off1]>>(short)3)&((short)0x1FFF)) | (w_short[(short)(off1+3)]<<leftShifts)); tmp[(short)(TMP1+2)]= (short) (((w_short[(short)(off1+1)]>>(short)3)&((short)0x1FFF)) | (w_short[off1]<<leftShifts)); tmp[(short)(TMP1+3)]= (short) (((w_short[(short)(off1+2)]>>(short)3)&((short)0x1FFF)) | (w_short[(short)(off1+1)]<<leftShifts)); tmp[TMP1]= (short) (((w_short[(short)(off1+3)]>>(short)3)&((short)0x1FFF)) | (w_short[(short)(off1+2)]<<leftShifts)) ; leftShifts = (short)(16-(short)13); tmp[(short)(TMP2+3)]= (short) (((w_short[off1]>>(short)13)&((short)0x0007)) | (w_short[(short)(off1+3)]<<leftShifts)); tmp[TMP2]= (short) (((w_short[(short)(off1+1)]>>(short)13)&((short)0x0007)) | (w_short[off1]<<leftShifts)); tmp[(short)(TMP2+1)]= (short) (((w_short[(short)(off1+2)]>>(short)13)&((short)0x0007)) | (w_short[(short)(off1+1)]<<leftShifts)); tmp[(short)(TMP2+2)]= (short) (((w_short[(short)(off1+3)]>>(short)13)&((short)0x0007)) | (w_short[(short)(off1+2)]<<leftShifts)) ; tmp[0]^=tmp[4]; tmp[1]^=tmp[5]; tmp[2]^=tmp[6]; tmp[3]^=tmp[7]; leftShifts = (short)(16-(short)6); tmp[TMP2]= (short) ((w_short[off1]>>(short)6)&((short)0x03FF)); tmp[(short)(TMP2+1)]= (short) (((w_short[(short)(off1+1)]>>(short)6)&((short)0x03FF)) | (w_short[off1]<<leftShifts)); tmp[(short)(TMP2+2)]= (short) (((w_short[(short)(off1+2)]>>(short)6)&((short)0x03FF)) | (w_short[(short)(off1+1)]<<leftShifts)); tmp[(short)(TMP2+3)]= (short) (((w_short[(short)(off1+3)]>>(short)6)&((short)0x03FF)) | (w_short[(short)(off1+2)]<<leftShifts)) ; w_short[wOff]=(short) (tmp[0]^tmp[4]); w_short[(short)(wOff+1)]=(short) (tmp[1]^tmp[5]); w_short[(short)(wOff+2)]=(short) (tmp[2]^tmp[6]); w_short[(short)(wOff+3)]=(short) (tmp[3]^tmp[7]) ; akku = 0; posy = (short)((off2)+3); posx = (short)((wOff)+3); addx=w_short[posx]; addy=w_short[posy]; w_short[posx] = (short)(addx+addy+akku); akku= (short)(( ((addx&addy)|((addx|addy) & ~w_short[posx])) >>15)&1); posy--; posx--; addx=w_short[posx]; addy=w_short[posy]; w_short[posx] = (short)(addx+addy+akku); akku= (short)(( ((addx&addy)|((addx|addy) & ~w_short[posx])) >>15)&1); posy--; posx--; addx=w_short[posx]; addy=w_short[posy]; w_short[posx] = (short)(addx+addy+akku); akku= (short)(( ((addx&addy)|((addx|addy) & ~w_short[posx])) >>15)&1); posy--; posx--; addx=w_short[posx]; addy=w_short[posy]; w_short[posx] = (short)(addx+addy+akku) ; leftShifts = (short)(16-(short)1); tmp[TMP1]= (short) (((w_short[off3]>>(short)1)&((short)0x7FFF)) | (w_short[(short)(off3+3)]<<leftShifts)); tmp[(short)(TMP1+1)]= (short) (((w_short[(short)(off3+1)]>>(short)1)&((short)0x7FFF)) | (w_short[off3]<<leftShifts)); tmp[(short)(TMP1+2)]= (short) (((w_short[(short)(off3+2)]>>(short)1)&((short)0x7FFF)) | (w_short[(short)(off3+1)]<<leftShifts)); tmp[(short)(TMP1+3)]= (short) (((w_short[(short)(off3+3)]>>(short)1)&((short)0x7FFF)) | (w_short[(short)(off3+2)]<<leftShifts)); ; leftShifts = (short)(16-(short)8); tmp[TMP2]= (short) (((w_short[off3]>>(short)8)&((short)0x00FF)) | (w_short[(short)(off3+3)]<<leftShifts)); tmp[(short)(TMP2+1)]= (short) (((w_short[(short)(off3+1)]>>(short)8)&((short)0x00FF)) | (w_short[off3]<<leftShifts)); tmp[(short)(TMP2+2)]= (short) (((w_short[(short)(off3+2)]>>(short)8)&((short)0x00FF)) | (w_short[(short)(off3+1)]<<leftShifts)); tmp[(short)(TMP2+3)]= (short) (((w_short[(short)(off3+3)]>>(short)8)&((short)0x00FF)) | (w_short[(short)(off3+2)]<<leftShifts)); ; tmp[0]^=tmp[4]; tmp[1]^=tmp[5]; tmp[2]^=tmp[6]; tmp[3]^=tmp[7]; leftShifts = (short)(16-(short)7); tmp[TMP2]= (short) ((w_short[off3]>>(short)7)&((short)0x01FF)); tmp[(short)(TMP2+1)]= (short) (((w_short[(short)(off3+1)]>>(short)7)&((short)0x01FF)) | (w_short[off3]<<leftShifts)); tmp[(short)(TMP2+2)]= (short) (((w_short[(short)(off3+2)]>>(short)7)&((short)0x01FF)) | (w_short[(short)(off3+1)]<<leftShifts)); tmp[(short)(TMP2+3)]= (short) (((w_short[(short)(off3+3)]>>(short)7)&((short)0x01FF)) | (w_short[(short)(off3+2)]<<leftShifts)) ; tmp[TMP1]=(short) (tmp[0]^tmp[4]); tmp[(short)(TMP1+1)]=(short) (tmp[1]^tmp[5]); tmp[(short)(TMP1+2)]=(short) (tmp[2]^tmp[6]); tmp[(short)(TMP1+3)]=(short) (tmp[3]^tmp[7]) ; akku = 0; posy = (short)((REG1)+3); posx = (short)((wOff)+3); addx=w_short[posx]; addy=tmp[posy]; w_short[posx] = (short)(addx+addy+akku); akku= (short)(( ((addx&addy)|((addx|addy) & ~w_short[posx])) >>15)&1); posy--; posx--; addx=w_short[posx]; addy=tmp[posy]; w_short[posx] = (short)(addx+addy+akku); akku= (short)(( ((addx&addy)|((addx|addy) & ~w_short[posx])) >>15)&1); posy--; posx--; addx=w_short[posx]; addy=tmp[posy]; w_short[posx] = (short)(addx+addy+akku); akku= (short)(( ((addx&addy)|((addx|addy) & ~w_short[posx])) >>15)&1); posy--; posx--; addx=w_short[posx]; addy=tmp[posy]; w_short[posx] = (short)(addx+addy+akku) ; akku = 0; posy = (short)((TMP1)+3); posx = (short)((wOff)+3); addx=w_short[posx]; addy=tmp[posy]; w_short[posx] = (short)(addx+addy+akku); akku= (short)(( ((addx&addy)|((addx|addy) & ~w_short[posx])) >>15)&1); posy--; posx--; addx=w_short[posx]; addy=tmp[posy]; w_short[posx] = (short)(addx+addy+akku); akku= (short)(( ((addx&addy)|((addx|addy) & ~w_short[posx])) >>15)&1); posy--; posx--; addx=w_short[posx]; addy=tmp[posy]; w_short[posx] = (short)(addx+addy+akku); akku= (short)(( ((addx&addy)|((addx|addy) & ~w_short[posx])) >>15)&1); posy--; posx--; addx=w_short[posx]; addy=tmp[posy]; w_short[posx] = (short)(addx+addy+akku) ; wOff=(short)(((short)(wOff+4))%64) ;


    		tmp[REG2]=K_SHORT[(short)(4*(round))]; tmp[(short)(REG2+1)]=K_SHORT[(short)(4*(round)+1)]; tmp[(short)(REG2+2)]=K_SHORT[(short)(4*(round)+2)]; tmp[(short)(REG2+3)]=K_SHORT[(short)(4*(round)+3)] ;


    		akku = 0; posy = (short)((REG2)+3); posx = (short)((REG1)+3); addx=tmp[posx]; addy=tmp[posy]; tmp[posx] = (short)(addx+addy+akku); akku= (short)(( ((addx&addy)|((addx|addy) & ~tmp[posx])) >>15)&1); posy--; posx--; addx=tmp[posx]; addy=tmp[posy]; tmp[posx] = (short)(addx+addy+akku); akku= (short)(( ((addx&addy)|((addx|addy) & ~tmp[posx])) >>15)&1); posy--; posx--; addx=tmp[posx]; addy=tmp[posy]; tmp[posx] = (short)(addx+addy+akku); akku= (short)(( ((addx&addy)|((addx|addy) & ~tmp[posx])) >>15)&1); posy--; posx--; addx=tmp[posx]; addy=tmp[posy]; tmp[posx] = (short)(addx+addy+akku) ;


			off1= (short)(((short)(hOff+28))%32);
    		akku = 0; posy = (short)((off1)+3); posx = (short)((REG1)+3); addx=tmp[posx]; addy=state[posy]; tmp[posx] = (short)(addx+addy+akku); akku= (short)(( ((addx&addy)|((addx|addy) & ~tmp[posx])) >>15)&1); posy--; posx--; addx=tmp[posx]; addy=state[posy]; tmp[posx] = (short)(addx+addy+akku); akku= (short)(( ((addx&addy)|((addx|addy) & ~tmp[posx])) >>15)&1); posy--; posx--; addx=tmp[posx]; addy=state[posy]; tmp[posx] = (short)(addx+addy+akku); akku= (short)(( ((addx&addy)|((addx|addy) & ~tmp[posx])) >>15)&1); posy--; posx--; addx=tmp[posx]; addy=state[posy]; tmp[posx] = (short)(addx+addy+akku) ;


    		off1=(short)(((short)(hOff+16))%32);
			off2=(short)(((short)(hOff+20))%32);
			off3=(short)(((short)(hOff+24))%32);
			tmp[REG2]= (short) ((state[off1] & state[off2]) ^ ((~state[off1]) & state[off3])); tmp[(short)(REG2+1)]= (short) ((state[(short)(off1+1)] & state[(short)(off2+1)]) ^ ((~state[(short)(off1+1)]) & state[(short)(off3+1)])); tmp[(short)(REG2+2)]= (short) ((state[(short)(off1+2)] & state[(short)(off2+2)]) ^ ((~state[(short)(off1+2)]) & state[(short)(off3+2)])); tmp[(short)(REG2+3)]= (short) ((state[(short)(off1+3)] & state[(short)(off2+3)]) ^ ((~state[(short)(off1+3)]) & state[(short)(off3+3)])) ;


    		akku = 0; posy = (short)((REG2)+3); posx = (short)((REG1)+3); addx=tmp[posx]; addy=tmp[posy]; tmp[posx] = (short)(addx+addy+akku); akku= (short)(( ((addx&addy)|((addx|addy) & ~tmp[posx])) >>15)&1); posy--; posx--; addx=tmp[posx]; addy=tmp[posy]; tmp[posx] = (short)(addx+addy+akku); akku= (short)(( ((addx&addy)|((addx|addy) & ~tmp[posx])) >>15)&1); posy--; posx--; addx=tmp[posx]; addy=tmp[posy]; tmp[posx] = (short)(addx+addy+akku); akku= (short)(( ((addx&addy)|((addx|addy) & ~tmp[posx])) >>15)&1); posy--; posx--; addx=tmp[posx]; addy=tmp[posy]; tmp[posx] = (short)(addx+addy+akku) ;


			off1=(short)(((short)(hOff+16))%32);
            leftShifts = (short)(16-(short)14); tmp[TMP1]= (short) (((state[off1]>>(short)14)&((short)0x0003)) | (state[(short)(off1+3)]<<leftShifts)); tmp[(short)(TMP1+1)]= (short) (((state[(short)(off1+1)]>>(short)14)&((short)0x0003)) | (state[off1]<<leftShifts)); tmp[(short)(TMP1+2)]= (short) (((state[(short)(off1+2)]>>(short)14)&((short)0x0003)) | (state[(short)(off1+1)]<<leftShifts)); tmp[(short)(TMP1+3)]= (short) (((state[(short)(off1+3)]>>(short)14)&((short)0x0003)) | (state[(short)(off1+2)]<<leftShifts)); ; leftShifts = (short)(16-(short)2); tmp[(short)(TMP2+1)]= (short) (((state[off1]>>(short)2)&((short)0x3FFF)) | (state[(short)(off1+3)]<<leftShifts)); tmp[(short)(TMP2+2)]= (short) (((state[(short)(off1+1)]>>(short)2)&((short)0x3FFF)) | (state[off1]<<leftShifts)); tmp[(short)(TMP2+3)]= (short) (((state[(short)(off1+2)]>>(short)2)&((short)0x3FFF)) | (state[(short)(off1+1)]<<leftShifts)); tmp[TMP2]= (short) (((state[(short)(off1+3)]>>(short)2)&((short)0x3FFF)) | (state[(short)(off1+2)]<<leftShifts)) ; tmp[0]^=tmp[4]; tmp[1]^=tmp[5]; tmp[2]^=tmp[6]; tmp[3]^=tmp[7]; leftShifts = (short)(16-(short)9); tmp[(short)(TMP2+2)]= (short) (((state[off1]>>(short)9)&((short)0x007F)) | (state[(short)(off1+3)]<<leftShifts)); tmp[(short)(TMP2+3)]= (short) (((state[(short)(off1+1)]>>(short)9)&((short)0x007F)) | (state[off1]<<leftShifts)); tmp[TMP2]= (short) (((state[(short)(off1+2)]>>(short)9)&((short)0x007F)) | (state[(short)(off1+1)]<<leftShifts)); tmp[(short)(TMP2+1)]= (short) (((state[(short)(off1+3)]>>(short)9)&((short)0x007F)) | (state[(short)(off1+2)]<<leftShifts)) ; tmp[REG2]=(short) (tmp[0]^tmp[4]); tmp[(short)(REG2+1)]=(short) (tmp[1]^tmp[5]); tmp[(short)(REG2+2)]=(short) (tmp[2]^tmp[6]); tmp[(short)(REG2+3)]=(short) (tmp[3]^tmp[7]) ;


    		akku = 0; posy = (short)((REG2)+3); posx = (short)((REG1)+3); addx=tmp[posx]; addy=tmp[posy]; tmp[posx] = (short)(addx+addy+akku); akku= (short)(( ((addx&addy)|((addx|addy) & ~tmp[posx])) >>15)&1); posy--; posx--; addx=tmp[posx]; addy=tmp[posy]; tmp[posx] = (short)(addx+addy+akku); akku= (short)(( ((addx&addy)|((addx|addy) & ~tmp[posx])) >>15)&1); posy--; posx--; addx=tmp[posx]; addy=tmp[posy]; tmp[posx] = (short)(addx+addy+akku); akku= (short)(( ((addx&addy)|((addx|addy) & ~tmp[posx])) >>15)&1); posy--; posx--; addx=tmp[posx]; addy=tmp[posy]; tmp[posx] = (short)(addx+addy+akku) ;


			off1= (short)(((short)(hOff+12))%32);
    		akku = 0; posy = (short)((REG1)+3); posx = (short)((off1)+3); addx=state[posx]; addy=tmp[posy]; state[posx] = (short)(addx+addy+akku); akku= (short)(( ((addx&addy)|((addx|addy) & ~state[posx])) >>15)&1); posy--; posx--; addx=state[posx]; addy=tmp[posy]; state[posx] = (short)(addx+addy+akku); akku= (short)(( ((addx&addy)|((addx|addy) & ~state[posx])) >>15)&1); posy--; posx--; addx=state[posx]; addy=tmp[posy]; state[posx] = (short)(addx+addy+akku); akku= (short)(( ((addx&addy)|((addx|addy) & ~state[posx])) >>15)&1); posy--; posx--; addx=state[posx]; addy=tmp[posy]; state[posx] = (short)(addx+addy+akku) ;



    		off1= (short)(((short)(hOff+4))%32);
			off2= (short)(((short)(hOff+8))%32);
			tmp[REG2]= (short) ((state[hOff] & state[off1]) ^ (state[hOff] & state[off2]) ^ (state[off1] & state[off2])); tmp[(short)(REG2+1)]= (short) ((state[(short)(hOff+1)] & state[(short)(off1+1)]) ^ (state[(short)(hOff+1)] & state[(short)(off2+1)]) ^ (state[(short)(off1+1)] & state[(short)(off2+1)])); tmp[(short)(REG2+2)]= (short) ((state[(short)(hOff+2)] & state[(short)(off1+2)]) ^ (state[(short)(hOff+2)] & state[(short)(off2+2)]) ^ (state[(short)(off1+2)] & state[(short)(off2+2)])); tmp[(short)(REG2+3)]= (short) ((state[(short)(hOff+3)] & state[(short)(off1+3)]) ^ (state[(short)(hOff+3)] & state[(short)(off2+3)]) ^ (state[(short)(off1+3)] & state[(short)(off2+3)])) ;


    		akku = 0; posy = (short)((REG2)+3); posx = (short)((REG1)+3); addx=tmp[posx]; addy=tmp[posy]; tmp[posx] = (short)(addx+addy+akku); akku= (short)(( ((addx&addy)|((addx|addy) & ~tmp[posx])) >>15)&1); posy--; posx--; addx=tmp[posx]; addy=tmp[posy]; tmp[posx] = (short)(addx+addy+akku); akku= (short)(( ((addx&addy)|((addx|addy) & ~tmp[posx])) >>15)&1); posy--; posx--; addx=tmp[posx]; addy=tmp[posy]; tmp[posx] = (short)(addx+addy+akku); akku= (short)(( ((addx&addy)|((addx|addy) & ~tmp[posx])) >>15)&1); posy--; posx--; addx=tmp[posx]; addy=tmp[posy]; tmp[posx] = (short)(addx+addy+akku) ;


            leftShifts = (short)(16-((short)12)); tmp[(short)(TMP1+1)]= (short) (((state[hOff]>>((short)12))&((short)0x000F)) | (state[(short)(hOff+3)]<<leftShifts)); tmp[(short)(TMP1+2)]= (short) (((state[(short)(hOff+1)]>>((short)12))&((short)0x000F)) | (state[hOff]<<leftShifts)); tmp[(short)(TMP1+3)]= (short) (((state[(short)(hOff+2)]>>((short)12))&((short)0x000F)) | (state[(short)(hOff+1)]<<leftShifts)); tmp[TMP1]= (short) (((state[(short)(hOff+3)]>>((short)12))&((short)0x000F)) | (state[(short)(hOff+2)]<<leftShifts)) ; leftShifts = (short)(16-((short)2)); tmp[(short)(TMP2+2)]= (short) (((state[hOff]>>((short)2))&((short)0x3FFF)) | (state[(short)(hOff+3)]<<leftShifts)); tmp[(short)(TMP2+3)]= (short) (((state[(short)(hOff+1)]>>((short)2))&((short)0x3FFF)) | (state[hOff]<<leftShifts)); tmp[TMP2]= (short) (((state[(short)(hOff+2)]>>((short)2))&((short)0x3FFF)) | (state[(short)(hOff+1)]<<leftShifts)); tmp[(short)(TMP2+1)]= (short) (((state[(short)(hOff+3)]>>((short)2))&((short)0x3FFF)) | (state[(short)(hOff+2)]<<leftShifts)) ; tmp[0]^=tmp[4]; tmp[1]^=tmp[5]; tmp[2]^=tmp[6]; tmp[3]^=tmp[7]; leftShifts = (short)(16-(short)7); tmp[(short)(TMP2+2)]= (short) (((state[hOff]>>(short)7)&((short)0x01FF)) | (state[(short)(hOff+3)]<<leftShifts)); tmp[(short)(TMP2+3)]= (short) (((state[(short)(hOff+1)]>>(short)7)&((short)0x01FF)) | (state[hOff]<<leftShifts)); tmp[TMP2]= (short) (((state[(short)(hOff+2)]>>(short)7)&((short)0x01FF)) | (state[(short)(hOff+1)]<<leftShifts)); tmp[(short)(TMP2+1)]= (short) (((state[(short)(hOff+3)]>>(short)7)&((short)0x01FF)) | (state[(short)(hOff+2)]<<leftShifts)) ; tmp[REG2]=(short) (tmp[0]^tmp[4]); tmp[(short)(REG2+1)]=(short) (tmp[1]^tmp[5]); tmp[(short)(REG2+2)]=(short) (tmp[2]^tmp[6]); tmp[(short)(REG2+3)]=(short) (tmp[3]^tmp[7]) ;


    		akku = 0; posy = (short)((REG2)+3); posx = (short)((REG1)+3); addx=tmp[posx]; addy=tmp[posy]; tmp[posx] = (short)(addx+addy+akku); akku= (short)(( ((addx&addy)|((addx|addy) & ~tmp[posx])) >>15)&1); posy--; posx--; addx=tmp[posx]; addy=tmp[posy]; tmp[posx] = (short)(addx+addy+akku); akku= (short)(( ((addx&addy)|((addx|addy) & ~tmp[posx])) >>15)&1); posy--; posx--; addx=tmp[posx]; addy=tmp[posy]; tmp[posx] = (short)(addx+addy+akku); akku= (short)(( ((addx&addy)|((addx|addy) & ~tmp[posx])) >>15)&1); posy--; posx--; addx=tmp[posx]; addy=tmp[posy]; tmp[posx] = (short)(addx+addy+akku) ;


    		state[(short)(((short)(hOff+28))%32)]= tmp[8];
    		state[(short)(((short)(hOff+29))%32)]= tmp[9];
    		state[(short)(((short)(hOff+30))%32)]= tmp[10];
    		state[(short)(((short)(hOff+31))%32)]= tmp[11];


    		hOff= (short)(((short)(32+hOff-4))%32);

    	}
    }
}
