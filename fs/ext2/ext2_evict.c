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
#define d(x) printk(KERN_ALERT "%d\n", x)

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

/* define structures */
struct clock_hand {
	long hand;
};

struct evicted {
	long evicted;
};

int ext2_evict(struct inode *i_node) {
	if (_debug_mode) { return 0;}
	
	if (atomic_read(&i_node->i_count) > 0) {
		/* inode has been mapped to a open file */
		printk(KERN_ALERT "inode %lu has been mapped to a open file", i_node->i_ino);
		return EMFILE;
	}

	 
	return 0;
}

int ext2_fetch(struct inode *i_node)
{
	if (_debug_mode) { return 0;}

	return 0;
}

static int time_greater(struct timespec *t1, struct timespec *t2)
{
	if (t1->tv_sec > t2->tv_sec)
		return 1;

	if (t1->tv_sec < t2->tv_sec)
		return 0;

	if (t1->tv_nsec > t2->tv_nsec)
		return 1;

	return 0;
}

int ext2_evict_fs(struct super_block *super)
{
	struct dentry *ext2_root = super->s_root;
	struct inode *root_inode = ext2_root->d_inode;
	struct ext2_sb_info *ext2_sup = super->s_fs_info;
	struct ext2_super_block *ext2_es = ext2_sup->s_es;
	struct inode *node;
	struct timespec *scan_time = kmalloc(sizeof(struct timespec), GFP_KERNEL);
	struct timespec *set_time;
	struct timespec *current_time = kmalloc(sizeof(struct timespec), GFP_KERNEL);
	struct clock_hand *clockhand = kmalloc(sizeof(struct clock_hand), GFP_KERNEL);
	struct evicted *set_evicted;
	int used_blocks = ext2_es->s_blocks_count - ext2_count_free_blocks(super);
	int total_blocks = ext2_es->s_blocks_count;
	int utility = (used_blocks * 1000) / total_blocks;
	long min_inode_number = (long) EXT2_FIRST_INO(super);
	long max_inode_number = (long) le32_to_cpu(ext2_es->s_inodes_count);
	long current_inode;
	int res;

	mutex_lock(&root_inode->i_mutex);
	res = ext2_xattr_get(root_inode, EXT2_XATTR_INDEX_TRUSTED, "clockhand", clockhand, sizeof(struct clock_hand));
	if (res < 0) {
		clockhand->hand = min_inode_number;
		current_inode = min_inode_number;
		printk(KERN_ALERT "min: %lu max: %lu\n", min_inode_number, max_inode_number);
		res = ext2_xattr_set(root_inode, EXT2_XATTR_INDEX_TRUSTED, "clockhand", clockhand, sizeof(struct clock_hand), XATTR_CREATE);
		
		mutex_unlock(&root_inode->i_mutex);
		if (res < 0) {
			printk(KERN_ALERT "Error in ext2_xattr_set.\n");
			return -1;
		}
	} else {
		mutex_unlock(&root_inode->i_mutex);
		current_inode = clockhand->hand;
		printk(KERN_ALERT "clock_hand: %lu\n", current_inode);
	}

	while (1) {
		node = ext2_iget(super, current_inode);
		if ((void *)node == (void *)(-ESTALE)) {
			++current_inode;

			if (current_inode > max_inode_number)
				current_inode = min_inode_number;
			continue;
		}
		mutex_lock(&node->i_mutex);
		
		if (!S_ISREG(node->i_mode) || atomic_read(&node->i_count) > 0) {
			++current_inode;

			if (current_inode > max_inode_number)
				current_inode = min_inode_number;

			mutex_unlock(&node->i_mutex);
			continue;
		}

		getnstimeofday(current_time);
		res = ext2_xattr_get(node, EXT2_XATTR_INDEX_TRUSTED, "scantime", scan_time, sizeof(struct timespec));
		if (res < 0) {
			scan_time->tv_sec = scan_time->tv_nsec = 0;
			set_time = kmalloc(sizeof(struct timespec), GFP_KERNEL);
			set_time->tv_sec = current_time->tv_sec;
			set_time->tv_nsec = current_time->tv_nsec;
			res = ext2_xattr_set(node, EXT2_XATTR_INDEX_TRUSTED, "scantime", set_time, sizeof(struct timespec), XATTR_CREATE);
			if (res < 0) {
				mutex_unlock(&node->i_mutex);
				printk(KERN_ALERT "Error in ext2_xattr_set create.\n");
				return -1;
			}
		} else {
			set_time = kmalloc(sizeof(struct timespec), GFP_KERNEL);
			set_time->tv_sec = current_time->tv_sec;
			set_time->tv_nsec = current_time->tv_nsec;
			res = ext2_xattr_set(node, EXT2_XATTR_INDEX_TRUSTED, "scantime", set_time, sizeof(struct timespec), XATTR_REPLACE);

			if (res < 0) {
				mutex_unlock(&node->i_mutex);
				printk(KERN_ALERT "Error in ext2_xattr_set replace.\n");
				return -1;
			}
		}

		if (time_greater(scan_time, &node->i_atime)) {
			printk(KERN_ALERT "Calling ext2_evict.\n");
			res = ext2_evict(node);
			set_evicted = kmalloc(sizeof(struct evicted), GFP_KERNEL);
			res = ext2_xattr_set(node, EXT2_XATTR_INDEX_TRUSTED, "evicted", set_evicted, sizeof(struct evicted), 0);
			if (res < 0) {
				printk(KERN_ALERT "Error in ext2_xattr_set.\n");
				return -1;
			}
			used_blocks = ext2_es->s_blocks_count - ext2_count_free_blocks(super);
			utility = (used_blocks * 1000) / total_blocks;

			if (utility < 10 * ext2_sup->evict) {
				clockhand = kmalloc(sizeof(struct clock_hand), GFP_KERNEL);
				clockhand->hand = current_inode;
				res = ext2_xattr_set(root_inode, EXT2_XATTR_INDEX_TRUSTED, "clockhand", clockhand, sizeof(struct clock_hand), XATTR_REPLACE);

				if (res < 0) {
					mutex_unlock(&node->i_mutex);
					printk(KERN_ALERT "Error in ext2_xattr_set replace.\n");
					return -1;
				} else {
					printk(KERN_ALERT "ext2_evict_fs return.\n");
					mutex_unlock(&node->i_mutex);
					return 0;
				}

			} else {
				++current_inode;

				if (current_inode > max_inode_number)
					current_inode = min_inode_number;

				mutex_unlock(&node->i_mutex);
				continue;
			}
		} else {
			++current_inode;

			if (current_inode > max_inode_number)
				current_inode = min_inode_number;

			mutex_unlock(&node->i_mutex);
			continue;
		}
	}
}
