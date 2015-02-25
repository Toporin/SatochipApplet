package org.satochip.applet;

import javacard.framework.Util;

/**
 * Memory Manager class.
 * <p>
 * 
 * An instance of this class is capable of handling allocation and deallocation
 * of chunks in a large Java byte array that is allocated once during the object
 * instantiation.
 * <p>
 * The Memory Manager allocates or frees memory chunks in the preallocated byte
 * array on demand.
 * <p>
 * 
 * No defragmentation is done, actually.
 * <p>
 * Consecutive freed memory chunks are recompacted.
 * <p>
 * 
 * Every allocation takes 2 more bytes to store the allocated block size, just
 * before the allocated offset.
 * <p>
 * 
 * A free memory block starts with a node (NODE_SIZE bytes):
 * 
 * <pre>
 * short size;
 * short next;
 * </pre>
 */

public class MemoryManager {
	/** Special offset value used as invalid offset */
	public final static short NULL_OFFSET = (short) 0xFFFF; // Also used as End
	// Of List
	private final static byte NODE_SIZE = (byte) 4;

	// All the available memory as a byte array
	private byte ptr[] = null;
	// Free memory list
	private short free_head = NULL_OFFSET;

	/**
	 * Constructor for the MemoryManager class
	 * 
	 * @param mem_size
	 *            Size of the memory are to be allocated
	 */
	public MemoryManager(short mem_size) {
		Init(mem_size);
	}

	private void Init(short mem_size) {
		if (ptr != null)
			return;
		// Allocate the memory
		ptr = new byte[mem_size];
		// Setup the free memory list
		// set the size
		Util.setShort(ptr, (short) 0, (short) mem_size);
		// set the pointer to EndOfList
		Util.setShort(ptr, (short) 2, (short) NULL_OFFSET);
		// set the pointer to the head node
		free_head = (short) 0;
	}

	/**
	 * Allocate memory
	 * <p>
	 * Each allocation takes actually a 2 bytes overhead.
	 * 
	 * @param size
	 *            Size of the memory block
	 * @return The offset at which allocated memory starts or NULL_OFFSET if an
	 *         error occurred.
	 * @see #free
	 * @see #freemem
	 */
	public short alloc(short size) {
		short offset = free_head;
		short prev = NULL_OFFSET;
		size = (short) (size + 2); // We need a 2 bytes more for block size
		// Forbid allocation of single bytes: when freeing,
		// they could remain isolated and a free node would not fit !
		if (size < NODE_SIZE)
			size = NODE_SIZE;

		// Search the free mem list for a suitable location
		// (no special memory management policies, at the moment)
		while (offset != NULL_OFFSET) {
			// System.out.println(offset);
			short free_size = Util.getShort(ptr, offset);
			short next_offset = Util.getShort(ptr, (short) (offset + 2));
			// System.out.println(free_size);
			// System.out.println(next_offset);
			if (free_size >= size) {
				// We've got it
				short remain = (short) (free_size - size);
				if (remain >= NODE_SIZE) {
					/*
					 * There's enough space for a new free mem node; * - just
					 * clamp this node (it won't move) * - previous node doesn't
					 * change at all
					 */
					Util.setShort(ptr, offset, remain);
				} else {
					/*
					 * Not enough space for a new free mem node; * - just
					 * allocate all the node's space * - previous node must skip
					 * to the next one
					 */
					size = free_size;
					remain = (short) 0;
					if (prev == NULL_OFFSET) {
						// No previous: it was the 1st
						free_head = next_offset;
					} else {
						// Previous: set it's next offset field
						Util.setShort(ptr, (short) (prev + 2), next_offset);
					}
				}
				/*
				 * Write the memory block size and skip it * while returning
				 * allocated offset (from * the tail of the free space)
				 */
				Util.setShort(ptr, (short) (offset + remain), size);
				return (short) (offset + remain + 2);
			} else {
				// Go to next list node
				prev = offset;
				offset = next_offset;
			}
		}
		/* No memory found ! */
		return NULL_OFFSET;
	}

	/**
	 * Gets the size of the greatest chunk of available memory
	 * 
	 * @return The size of the greatest free memory chunk, or zero if there is
	 *         no free mem left
	 */
	public short getMaxSize() {
		short max_size = 2;
		short base = free_head;
		while (base != NULL_OFFSET) {
			short size = Util.getShort(ptr, base);
			if (size > max_size)
				max_size = size;
			base = Util.getShort(ptr, (short) (base + 2));
		}
		return (short) (max_size - 2);
	}

	/**
	 * Free a memory block
	 * <p>
	 * Consecutive free blocks are recompacted. Recompaction happens on free().
	 * 4 cases are considered: don't recompact, recompact with next only, with
	 * previous only and with both of them.
	 * 
	 * @param offset
	 *            The offset at which the memory block starts; it was returned
	 *            from a previous call to {@link #alloc}
	 * @see #alloc
	 * @see #freemem
	 */
	public void free(short offset) {
		offset -= 2;
		short size = Util.getShort(ptr, offset);

		/* Search for the right insertion point */
		short prev = NULL_OFFSET;
		short base = free_head;
		boolean found = false;
		short node_next = (short) 0; // Compiler warning...
		while (base != NULL_OFFSET) {
			node_next = Util.getShort(ptr, (short) (base + 2));
			if (offset < base) {
				found = true;
				break;
			}
			prev = base;
			base = node_next;
		}

		/* Check if can recompact with next */

		if (found && ((short) (offset + size) == base)) {
			/*
			 * Recompact with next: extract next from list * so we handle a
			 * single case, after compacting * next with new node to be inserted
			 */
			size += Util.getShort(ptr, base);
			/*
			 * We have to rewrite down the right size, in case it becomes a new
			 * node
			 */
			Util.setShort(ptr, offset, size);
			if (prev != NULL_OFFSET)
				Util.setShort(ptr, (short) (prev + 2), node_next);
			else
				free_head = node_next;
			base = node_next;
		}

		/* Check if can recompact with previous */
		if (prev != NULL_OFFSET) {
			short prev_size = Util.getShort(ptr, prev);
			if ((short) (prev + prev_size) == offset) {
				/* Recompact with previous and don't insert a new node */
				Util.setShort(ptr, prev, (short) (prev_size + size));
			} else {
				/* Couldn't recompact: insert node after previous */
				// Write node next pointer only (size is already in place)
				Util.setShort(ptr, (short) (offset + 2), base);
				Util.setShort(ptr, (short) (prev + 2), offset);
			}
		} else {
			/* Couldn't recompact with prev; head-insert new node */
			// Write node next pointer only (size is already in place)
			Util.setShort(ptr, (short) (offset + 2), base);
			free_head = offset;
		}
	}

	/**
	 * Get the size of a memory block
	 * 
	 * @param offset
	 *            The offset at which the memory block starts
	 */
	public short getBlockSize(short offset) {
		return (short) (Util.getShort(ptr, (short) (offset - 2)) - 2);
	}

	/**
	 * Get available free memory
	 * 
	 * @return The total amount of available free memory, equal to the sum of
	 *         all free fragments' sizes.
	 * @see free
	 * @see alloc
	 */
	public short freemem() {
		short offset = free_head;
		short total = (short) 0;
		// Scan free mem list
		while (offset != NULL_OFFSET) {
			// Return free memory in case that every single free block
			// is entirely allocated at once (best case)
			// (every allocation keeps 2 bytes for block size)
			total = (short) (total + Util.getShort(ptr, offset) - 2);
			offset = Util.getShort(ptr, (short) (offset + 2));
		}
		return total;
	}

	/**
	 * Resize (only clamping is supported) a previously allocated memory chunk
	 * <p>
	 * 
	 * @param offset
	 *            Memory offset as returned by alloc()
	 * @param size
	 *            New size of the memory block
	 * @return True if it was possible to realloc(), False otherwise
	 * @see #alloc
	 * @see #free
	 * @see #freemem
	 */
	public boolean realloc(short offset, short new_size) {
		short actual_size = Util.getShort(ptr, (short) (offset - 2));
		new_size += (short) 2;
		if ((new_size < (short) (1 + 2)) || ((short) (actual_size - new_size) < NODE_SIZE))
			// Cannot free any memory (really here there are issues...)
			return false;
		// Clamp this node
		Util.setShort(ptr, (short) (offset - 2), new_size);
		// Create a fake allocated node
		Util.setShort(ptr, (short) (offset + new_size - 2), (short) (actual_size - new_size));
		// Deallocate the freed memory
		free((short) (offset + new_size));
		return true;
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

	/**
	 * Set a byte value into memory
	 * 
	 * @param base
	 *            The complete memory location (offset) of the byte to set
	 * @param b
	 *            The new byte value
	 */
	public void setByte(short base, byte b) {
		ptr[base] = b;
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
	 * Read a byte value from memory
	 * 
	 * @param base
	 *            The complete memory location (offset) of the byte to read
	 * @return The byte value
	 */
	public byte getByte(short base) {
		return ptr[base];
	}

	/**
	 * Set a short value into memory
	 * 
	 * @param base
	 *            The base memory location (offset) of the short to set
	 * @param offset
	 *            The offset of the short (is added to the base parameter)
	 * @param b
	 *            The short value
	 */
	public void setShort(short base, short offset, short b) {
		Util.setShort(ptr, (short) (base + offset), b);
	}

	/**
	 * Set a short value into memory
	 * 
	 * @param base
	 *            The complete memory location (offset) of the short to set
	 * @param b
	 *            The short value
	 */
	public void setShort(short base, short b) {
		Util.setShort(ptr, base, b);
	}

	/**
	 * Read a short value from memory
	 * 
	 * @param base
	 *            The base memory location (offset) of the short to read
	 * @param offset
	 *            The offset of the short (is added to the base parameter)
	 * @return The short value
	 */
	public short getShort(short base, short offset) {
		return Util.getShort(ptr, (short) (base + offset));
	}

	/**
	 * Read a short value from memory
	 * 
	 * @param base
	 *            The base memory location (offset) of the short to read
	 * @return The short value
	 */
	public short getShort(short base) {
		return Util.getShort(ptr, base);
	}

	/**
	 * Copy a byte sequence into memory
	 * 
	 * @param dst_base
	 *            The base memory location (offset) of the destination byte
	 *            sequence
	 * @param dst_offset
	 *            The offset of the destination byte sequence (is added to the
	 *            dst_base parameter)
	 * @param src_bytes
	 *            The source byte array
	 * @param src_offset
	 *            The offset at which the source sequence starts in src_bytes[]
	 * @param size
	 *            The number of bytes to be copied
	 */
	public void setBytes(short dst_base, short dst_offset, byte[] src_bytes, short src_offset, short size) {
		Util.arrayCopy(src_bytes, src_offset, ptr, (short) (dst_base + dst_offset), size);
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
	 * Retrieve the Java byte array containing all the memory contents. To
	 * optimize, we don't use external buffers, * but we directly copy from the
	 * memory array * Use this function only if really required. *
	 * 
	 * @return The Java byte array containing all memory contents
	 */
	public byte[] getBuffer() {
		return ptr;
	}
} // class MemoryManager
