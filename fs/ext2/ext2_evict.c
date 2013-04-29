#include <linux/module.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/blkdev.h>
#include <linux/parser.h>
#include <linux/random.h>
#include <linux/buffer_head.h>
#include <linux/exportfs.h>
#include <linux/smp_lock.h>
#include <linux/vfs.h>
#include <linux/seq_file.h>
#include <linux/mount.h>
#include <linux/log2.h>
#include <linux/quotaops.h>
#include <asm/uaccess.h>
#include "ext2.h"
#include "xattr.h"
#include "acl.h"
#include "xip.h"

#define SERVER_IP "10.0.2.2"
#define EVICT_PORT 8888

static int _debug_mode = 1;

/* Evict the file identified by i_node to the cloud server,
* freeing its disk blocks and removing any page cache pages.
* The call should return when the file is evicted. Besides
* the file data pointers, no other metadata, e.g., access time,
* size, etc. should be changed. Appropriate errors should
* be returned. In particular, the operation should fail if the
* inode currently maps to an open file. Lock the inode
* appropriately to prevent a file open operation on it while
* it is being evicted.
*/ 

int ext2_evict(struct inode *i_node) {
	if (_debug_mode) { return 0;}
	
	if (atomic_read(i_node->i_count) > 0) {
		/* inode has been mapped to a open file */
		printk(KERN_ALERT "inode %lu has been mapped to a open file", inode->i_ino);
		return EMFILE;
	}

	 
	return 0;
}

int ext2_fetch(struct inode *i_node)
{
	if (_debug_mode) { return 0;}

	return 0;
}

int ext2_evict_fs(struct super_block *super)
{
	return 0;
}

