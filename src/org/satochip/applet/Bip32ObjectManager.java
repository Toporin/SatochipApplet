/*
 * SatoChip Bitcoin Hardware Wallet based on javacard
 * (c) 2015-2019 by Toporin - 16DMCk4WUaHofchAhpMaQS4UPm4urcy2dN
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
import javacard.framework.ISOException;

/**
 * Bip32 Object Manager Class
 * <p>
 * 
 * Objects are simply stored in an array in the dynamic memory
 * Object have a fixed size
 * The first bytes are used as id to store/retrieve corresponding data 
 * <p>
 * 
 * Object fields:
 * <pre>
 *   byte[] data
 *   the first size_id bytes are used to identify the stored data
 * </pre>
 */

public class Bip32ObjectManager {
    
    /** There have been memory problems on the card */
    public final static short SW_NO_MEMORY_LEFT = (short) 0x9C01;

    public final static short NULL_OFFSET = (short) 0xFFFF; // Also used as End
    
    // All the available memory as a byte array
    private byte ptr[] = null;
    public byte empty[] = null;
    public short nb_elem_free;
    public short nb_elem_used;
    private short size_elem; 
    private short size_id;
    private short size;
    
    /**
     * Constructor for the Bip32ObjectManager class.
     * 
     * @param nb_elem
     *          Max number of elements stored in the array
     * @param size_elem
     *          Size of each element (fixed)
     * @param size_id
     *          Size of data used to id the object.
     *          The first size_id bytes of data are used for comparison
     */
    public Bip32ObjectManager(short nb_elem, short size_elem, short size_id) {
        if (ptr != null)
            return;
        if (size_id>size_elem)
            return;
        // Allocate the memory
        size= (short) (nb_elem*size_elem);
        ptr = new byte[size];
        empty  = new byte[size_id]; //to efficiently(?) check for empty elements
        Util.arrayFillNonAtomic(empty, (short)0, size_id, (byte)0);
        this.nb_elem_free= nb_elem;
        this.nb_elem_used= (short)0;
        this.size_elem= size_elem;
        this.size_id=size_id;
    }

    /**
     * Creates an object by reserving a fixed memory size for it.
     * Throws a SW_NO_MEMORY_LEFT exception if cannot allocate the memory.
     * 
     * @param src
     *            the source array to copy from
     * @param srcOff
     *            the offset for the source array
     *            
     * @return The memory base address for the object.
     */
    public short createObject(byte[] src, short srcOff) {
        if (nb_elem_free == 0)
            ISOException.throwIt(SW_NO_MEMORY_LEFT);        
        
        short base=0;
        while (base<this.size) {
            if (Util.arrayCompare(this.ptr, base, this.empty, (short)0, this.size_id)==0){
                Util.arrayCopyNonAtomic(src, srcOff, this.ptr, base, this.size_elem);
                this.nb_elem_free--;
                this.nb_elem_used++;
                return base;
            }
            base+=this.size_elem;   
        }
        return NULL_OFFSET;//should not happen
    }

    /**
     * Destroy the object starting with specific value
     * 
     * @param src
     *            a byte array to compare object with
     * @param srcOff
     *            the offset for the source array
     */
    public void destroyObject(byte[] src, short srcOff){
        short base = 0;
        while (base<this.size) {
            if (Util.arrayCompare(src, srcOff, this.ptr, base, this.size_id)==0){
                Util.arrayFillNonAtomic(this.ptr, base, this.size_elem, (byte)0x00);
                this.nb_elem_free++;
                this.nb_elem_used--;
                return;
            }
            base+=this.size_elem;
        }   
    }
    
    public short reset(){
        short base = 0;
        short nb_deleted=0;
        while (base<this.size) {
            if (Util.arrayCompare(this.ptr, base, this.empty, (short)0, this.size_id)!=0){
                Util.arrayFillNonAtomic(this.ptr, base, this.size_elem, (byte)0x00);
                this.nb_elem_free++;
                this.nb_elem_used--;
                nb_deleted++;
            }
            base+=this.size_elem;
        }
        return nb_deleted;
    }
    
    /**
    1 * Returns the object base address (offset) for an object that start with data provided in array
     * <p>
     * 
     * @param src
     *            a byte array to compare object with
     * @param srcOff
     *            the offset for the source array
     */
    public short getBaseAddress(byte[] src, short srcOff) {
        short base = 0;
        while (base<this.size) {
            if (Util.arrayCompare(src, srcOff, this.ptr, base, this.size_id)==0){
                return base;
            }
            base+=this.size_elem;
        }
        return NULL_OFFSET;
    }
    
    /**
     * Copy a byte sequence from memory
     * 
     * @param dst_bytes
     *            The destination byte array
     * @param dst_offset
     *            The offset at which the sequence will be copied in dst_bytes[]
     * @param src_base
     *            The base memory location (offset) of the source byte sequence
     * @param src_offset
     *            The offset of the source byte sequence (is added to the
     *            src_base parameter)
     * @param size
     *            The number of bytes to be copied
     */
    public void getBytes(byte[] dst_bytes, short dst_offset, short src_base, short src_offset, short size) {
        Util.arrayCopy(ptr, (short) (src_base + src_offset), dst_bytes, dst_offset, size);
    }
    
    /**
     * Read a byte value from memory
     * 
     * @param base
     *            The base memory location (offset) of the byte to read
     * @param offset
     *            The offset of the byte (is added to the base parameter)
     * @return The byte value
     */
    public byte getByte(short base, short offset) {
        return ptr[(short) (base + offset)];
    }
    
    /**
     * Set a byte value into memory
     * 
     * @param base
     *            The base memory location (offset) of the byte to set
     * @param offset
     *            The offset of the byte (is added to the base parameter)
     * @param b
     *            The new byte value
     */
    public void setByte(short base, short offset, byte b) {
        ptr[(short) (base + offset)] = b;
    }
        
} // class Bip32ObjectManager
