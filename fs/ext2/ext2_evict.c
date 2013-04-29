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

int ext2_evict(struct inode *i_node)
{
	return 0;
}

int ext2_fetch(struct inode *i_node)
{
	return 0;
}

int ext2_evict_fs(struct super_block *super)
{
	return 0;
}