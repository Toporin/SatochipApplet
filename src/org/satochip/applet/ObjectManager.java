package org.satochip.applet;

import org.satochip.applet.MemoryManager;

import javacard.framework.Util;
import javacard.framework.ISOException;

/**
 * Object Manager Class
 * <p>
 * 
 * Objects are linked in a list in the dynamic memory. No smart search is done
 * at the moment.
 * <p>
 * 
 * Object fields:
 * 
 * <pre>
 *   short next (2 byte)
 *   short obj_class (2 bytes)
 *   short obj_id (2 bytes)
 *   byte[] ACL (6 bytes)
 *   short obj_size (2 bytes)
 *   byte[] data
 * </pre>
 * 
 * TODO - Could we definitively avoid a map enforcing the ID (equal to the
 * memory address, i.e.) - security implications ?
 * 
 */

public class ObjectManager {

	public final static byte OBJ_ACL_SIZE = (byte) 6;

	private final static byte OBJ_HEADER_SIZE = (byte) (6 + OBJ_ACL_SIZE + 2);
	private final static byte OBJ_H_NEXT = (byte) 0; // Short size;
	private final static byte OBJ_H_CLASS = (byte) 2; // Short ocj_class;
	private final static byte OBJ_H_ID = (byte) 4; // Short obj_id;
	private final static byte OBJ_H_ACL = (byte) 6; // Byte[OBJ_ACL_SIZE] acl;
	private final static byte OBJ_H_SIZE = (byte) 12; // Short size;
	private final static byte OBJ_H_DATA = (byte) 14;

	/** There have been memory problems on the card */
	public final static short SW_NO_MEMORY_LEFT = (short) 0x9C01;

	/**
	 * Size of an Object Record filled by getFirstRecord() or getNextRecord():
	 * ID, Size, ACL
	 */
	public final static short RECORD_SIZE = (short) (4 + 4 + OBJ_ACL_SIZE);

	/**
	 * Iterator on objects. Stores the offset of the last retrieved object's
	 * record.
	 */
	private short it;

	/** The Memory Manager object */
	private MemoryManager mem = null;

	/** Map for fast search of objects (unimplemented) */
	// static Map map;

	/** Head of the objects' list */
	private short obj_list_head = MemoryManager.NULL_OFFSET;

	/**
	 * Constructor for the ObjectManager class.
	 * 
	 * @param mem_ref
	 *            The MemoryManager object to be used to allocate objects'
	 *            memory.
	 */
	public ObjectManager(MemoryManager mem_ref) {
		mem = mem_ref;
		// map = new Map();
		obj_list_head = MemoryManager.NULL_OFFSET;
	}

	/**
	 * Creates an object with specified parameters. Throws a SW_NO_MEMORY_LEFT
	 * exception if cannot allocate the memory. Does not check if object exists.
	 * 
	 * @param type
	 *            Object Type
	 * @param id
	 *            Object ID (Type and ID form a generic 4 bytes identifier)
	 * @param acl_buf
	 *            Java byte array containing the ACL for the new object
	 * @param acl_offset
	 *            Offset at which the ACL starts in acl_buf[]
	 * @return The memory base address for the object. It can be used in
	 *         successive calls to xxxFromAddress() methods.
	 */
	public short createObject(short type, short id, short size, byte[] acl_buf, short acl_offset) {
		/* Allocate memory for new object */
		short base = mem.alloc((short) (size + OBJ_HEADER_SIZE));
		if (base == MemoryManager.NULL_OFFSET)
			ISOException.throwIt(SW_NO_MEMORY_LEFT);
		/* New obj will be inserted in the head of the list */
		mem.setShort(base, OBJ_H_NEXT, obj_list_head);
		mem.setShort(base, OBJ_H_CLASS, type);
		mem.setShort(base, OBJ_H_ID, id);
		mem.setShort(base, OBJ_H_SIZE, size);
		mem.setBytes(base, OBJ_H_ACL, acl_buf, acl_offset, OBJ_ACL_SIZE);
		obj_list_head = base;

		/* Add to the map */
		// map.addEntry(type, id, base);

		// Return base address
		return (short) (base + OBJ_HEADER_SIZE);
	}

	/** Creates an object with the maximum available size */
	public short createObjectMax(short type, short id, byte[] acl_buf, short acl_offset) {
		short obj_size = mem.getMaxSize();
		if (obj_size == (short) 0)
			ISOException.throwIt(SW_NO_MEMORY_LEFT);
		/*
		 * The object's real size must take into account that * extra bytes are
		 * needed for the header
		 */
		return createObject(type, id, (short) (obj_size - OBJ_HEADER_SIZE), acl_buf, acl_offset);
	}

	/**
	 * Clamps an object freeing the unused memory
	 * 
	 * @param type
	 *            Object Type
	 * @param id
	 *            Object ID (Type and ID form a generic 4 bytes identifier)
	 * @param new_size
	 *            The new object size (must be less than current size)
	 * @return True if clamp was possible, false otherwise
	 */
	public boolean clampObject(short type, short id, short new_size) {
		short base = getEntry(type, id);
		if (base == (short) MemoryManager.NULL_OFFSET)
			ISOException.throwIt((short) 0x9C07);
		// Delegate every check to the Memory Manager
		if (mem.realloc(base, (short) (new_size + OBJ_HEADER_SIZE))) {
			mem.setShort(base, OBJ_H_SIZE, new_size);
			return true;
		}
		return false;
	}

	/** Set the object's ACL. Unused at the moment. */
	private void setACL(short type, short id, byte[] acl_buf, short acl_offset) {
		short base = getEntry(type, id);
		mem.setBytes(base, OBJ_H_ACL, acl_buf, acl_offset, OBJ_ACL_SIZE);
	}

	/**
	 * Allow or disallow read on object given the logged identities
	 * 
	 * @param base
	 *            The object base address as returned from getBaseAddress()
	 * @param logged_ids
	 *            The current logged in identities as stored in
	 *            CardEdge.logged_ids
	 */
	public boolean authorizeReadFromAddress(short base, short logged_ids) {
		return authorizeOp(mem.getShort(base, (short) (OBJ_H_ACL - OBJ_HEADER_SIZE)), logged_ids);
	}

	/**
	 * Allow or unallow write on object given the logged identities
	 * 
	 * @param base
	 *            The object base address as returned from getBaseAddress()
	 * @param logged_ids
	 *            The current logged in identities as stored in
	 *            CardEdge.logged_ids
	 */
	public boolean authorizeWriteFromAddress(short base, short logged_ids) {
		return authorizeOp(mem.getShort(base, (short) (OBJ_H_ACL + (short) 2 - OBJ_HEADER_SIZE)), logged_ids);
	}

	/**
	 * Allow or unallow delete on object given the logged identities
	 * 
	 * @param base
	 *            The object base address as returned from getBaseAddress()
	 * @param logged_ids
	 *            The current logged in identities as stored in
	 *            CardEdge.logged_ids
	 */
	public boolean authorizeDeleteFromAddress(short base, short logged_ids) {
		return authorizeOp(mem.getShort(base, (short) (OBJ_H_ACL + (short) 4 - OBJ_HEADER_SIZE)), logged_ids);
	}

	/**
	 * Check if logged in identities satisfy requirements for an operation
	 * 
	 * @param required_ids
	 *            The required identities as from an ACL short
	 * @param logged_ids
	 *            The current logged in identities as stored in
	 *            CardEdge.logged_ids
	 */
	private boolean authorizeOp(short required_ids, short logged_ids) {
		return ((required_ids != (short) 0xFFFF) && (((short) (required_ids & logged_ids)) == required_ids));
	}

	/** Write data at the specified location in an object */
	// public void setObjectData(short type, short id, short dst_offset,
	// byte[] src_data, short src_offset,
	// short len) {
	// // TODO: short dst_base = map.getEntry(type, id);
	// short dst_base = getEntry(type, id);
	// mem.setBytes(dst_base, dst_offset, src_data, src_offset, len);
	// }

	// /** Read data from the specified location in an object */
	// public void getObjectData(byte[] dst_data, short dst_offset,
	// short type, short id, short src_offset,
	// short len) {
	// // TODO: short dst_base = map.getEntry(type, id);
	// short src_base = getEntry(type, id);
	// mem.getBytes(dst_data, dst_offset, src_base, src_offset, len);
	// }

	/**
	 * Destroy the specified object
	 * 
	 * @param type
	 *            Object Type
	 * @param id
	 *            Object ID (Type and ID form a generic 4 bytes identifier)
	 * @param secure
	 *            If true, object memory is zeroed before being released.
	 */
	public void destroyObject(short type, short id, boolean secure) {
		short base = obj_list_head;
		short prev = MemoryManager.NULL_OFFSET;
		boolean found = false;
		while ((!found) && (base != MemoryManager.NULL_OFFSET)) {
			if ((mem.getShort(base, OBJ_H_CLASS) == type) && (mem.getShort(base, OBJ_H_ID) == id))
				found = true;
			else {
				prev = base;
				base = mem.getShort(base, OBJ_H_NEXT);
			}
		}
		if (found) {
			// Unlink object from the list
			if (prev != MemoryManager.NULL_OFFSET) {
				mem.setShort(prev, OBJ_H_NEXT, mem.getShort(base, OBJ_H_NEXT));
			} else {
				obj_list_head = mem.getShort(base, OBJ_H_NEXT);
			}
			// Zero memory if required
			if (secure)
				Util.arrayFillNonAtomic(mem.getBuffer(), (short) (base + OBJ_HEADER_SIZE), mem.getShort(base,
						OBJ_H_SIZE), (byte) 0x00);

			// Free memory
			mem.free(base);
		}
	}

	/**
	 * Returns the header base address (offset) for the specified object
	 * <p>
	 * Object header is found at the returned offset, while object data starts
	 * right after the header
	 * <p>
	 * This performs a linear search, so performance issues could arise as the
	 * number of objects grows If object is not found, then returns NULL_OFFSET
	 * 
	 * @param type
	 *            Object Type
	 * @param id
	 *            Object ID (Type and ID form a generic 4 bytes identifier)
	 * @return The starting offset of the object or NULL_OFFSET if the object is
	 *         not found.
	 */
	private short getEntry(short type, short id) {
		/*
		 * This is a stupid linear search. It's fine for a few objects. TODO:
		 * Use a map for high number of objects
		 */
		short base = obj_list_head;
		while (base != MemoryManager.NULL_OFFSET) {
			if ((mem.getShort(base, OBJ_H_CLASS) == type) && (mem.getShort(base, OBJ_H_ID) == id))
				return base;
			base = mem.getShort(base, OBJ_H_NEXT);
		}
		return MemoryManager.NULL_OFFSET;
	}

	/**
	 * Returns the data base address (offset) for an object.
	 * <p>
	 * The base address can be used for further calls to xxxFromAddress()
	 * methods
	 * <p>
	 * This function should only be used if performance issue arise.
	 * setObjectData() and getObjectData() should be used, instead.
	 * 
	 * @param type
	 *            Object Type
	 * @param id
	 *            Object ID (Type and ID form a generic 4 bytes identifier)
	 * @return The starting offset of the object. At this location
	 */
	public short getBaseAddress(short type, short id) {
		short base = getEntry(type, id);
		if (base == MemoryManager.NULL_OFFSET)
			return MemoryManager.NULL_OFFSET;
		else
			return ((short) (base + OBJ_HEADER_SIZE));
	}

	/**
	 * Checks if an object exists
	 * 
	 * @param type
	 *            The object type
	 * @param id
	 *            The object ID
	 * @return true if object exists
	 */
	public boolean exists(short type, short id) {
		short base = getEntry(type, id);
		return (base != MemoryManager.NULL_OFFSET);
	}

	/** Returns object size from the base address */
	public short getSizeFromAddress(short base) {
		return mem.getShort((short) (base - OBJ_HEADER_SIZE + OBJ_H_SIZE));
	}

	/**
	 * Resets the objects iterator and retrieves the information record of the
	 * first object, if any.
	 * <p>
	 * 
	 * @param buffer
	 *            The byte array into which the record will be copied
	 * @param offset
	 *            The offset in buffer[] at which the record will be copied
	 * @return True if an object was found. False if there are no objects.
	 * 
	 * @see #getNextRecord
	 */
	public boolean getFirstRecord(byte[] buffer, short offset) {
		it = obj_list_head;
		return getNextRecord(buffer, offset);
	}

	/**
	 * Retrieves the information record of the next object, if any.
	 * <p>
	 * 
	 * @param buffer
	 *            The byte array into which the record will be copied
	 * @param offset
	 *            The offset in buffer[] at which the record will be copied
	 * @return True if an object was found. False if there are no more objects
	 *         to inspect.
	 * @see #getFirstRecord
	 */
	public boolean getNextRecord(byte[] buffer, short offset) {
		if (it == MemoryManager.NULL_OFFSET)
			return false;
		// Setting Object Class
		Util.setShort(buffer, offset, mem.getShort(it, OBJ_H_CLASS));
		// Setting Object ID
		Util.setShort(buffer, (short) (offset + 2), mem.getShort(it, OBJ_H_ID));
		// Setting Size's M.S.Short to zero.
		Util.setShort(buffer, (short) (offset + 4), (short) 0);
		// Setting Size's L.S.Short
		Util.setShort(buffer, (short) (offset + 6), mem.getShort(it, (short) OBJ_H_SIZE));
		// Setting ACL
		Util.arrayCopyNonAtomic(mem.getBuffer(), (short) (it + OBJ_H_ACL), buffer, (short) (offset + 8), OBJ_ACL_SIZE);
		// Advance iterator
		it = mem.getShort(it, OBJ_H_NEXT);
		return true;
	}

	/**
	 * Compare an object's ACL with the provided ACL.
	 * 
	 * @param base
	 *            The object base address, as returned from getBaseAddress()
	 * @param acl
	 *            The buffer containing the ACL
	 * @return True if the ACLs are equal
	 */
	public boolean compareACLFromAddress(short base, byte[] acl) {
		return (Util.arrayCompare(mem.getBuffer(), (short) (base - OBJ_HEADER_SIZE + OBJ_H_ACL), acl, (short) 0,
				OBJ_ACL_SIZE) == (byte) 0);
	}

} // class MemoryManager
