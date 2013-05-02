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
#include <linux/kthread.h>
#include <linux/delay.h>
#include <asm/uaccess.h>

/* define macros */
#define SECONDS_PER_MINUTE 60

static int evict_daemon(void *data)
{
	struct file_system_type *p;
	struct super_block *sup;

	while (1) {
		p = get_fs_type("ext2");
		if (p) {
			list_for_each_entry(sup, &p->fs_supers, s_instances) {
				mutex_lock(&sup->s_lock);
				if (sup->s_op && sup->s_op->evict_fs) {
					sup->s_op->evict_fs(sup);
				}
				mutex_unlock(&sup->s_lock);
			}

			msleep(SECONDS_PER_MINUTE * 1000);
		} else {
			msleep(SECONDS_PER_MINUTE * 1000);
		}
	}

	return 0;
}

static int __init kfs_evictd(void)
{
	struct task_struct *p;

	p = kthread_run(evict_daemon, NULL, "evict_daemon");

	return 0;
}

fs_initcall(kfs_evictd);