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

#include <linux/net.h>
#include <net/sock.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/file.h>
#include <linux/socket.h>
#include <linux/smp_lock.h>

#include "ext2.h"
#include "xattr.h"
#include "acl.h"
#include "xip.h"

#define d(x) printk(KERN_ALERT "%d\n", x)

enum clfs_status {
	CLFS_OK = 0,            /* Success */
	CLFS_INVAL = EINVAL,    /* Invalid address */
	CLFS_ACCESS = EACCES,   /* Could not read/write file */
	CLFS_ERROR              /* Other errors */
};

enum clfs_type {
	CLFS_PUT,
	CLFS_GET,
	CLFS_RM
};

struct clfs_req {
	enum clfs_type type;
	unsigned long inode;
	unsigned long size;
};

struct clock_hand {
	long hand;
};

struct evicted {
	long evicted;
};

DEFINE_SPINLOCK(wc_check_lock);

static unsigned int inet_addr(char *str)
{
	int a,b,c,d;
	char arr[4];
	sscanf(str,"%d.%d.%d.%d",&a,&b,&c,&d);
	arr[0] = a; arr[1] = b; arr[2] = c; arr[3] = d;
	return *(unsigned int*)arr;
}

static inline void __prepare_addr(struct sockaddr_in *addr, struct inode*i) {

	addr->sin_family = AF_INET;
	addr->sin_port = htons(((struct ext2_sb_info *)i->i_sb->s_fs_info)->port);
	addr->sin_addr.s_addr = inet_addr(((struct ext2_sb_info *)i->i_sb->s_fs_info)->ip);

	printk(KERN_ALERT "IP: %s, port: %d\n", ((struct ext2_sb_info *)i->i_sb->s_fs_info)->ip, ntohs(addr->sin_port));

}

static inline int __connect_socket(struct socket *socket,
				   struct sockaddr_in* server_addr,
				   struct inode* i)
{
	int r = 0;
	r = socket->ops->connect(socket, 
				 (struct sockaddr *) server_addr,
				 sizeof(struct sockaddr), 0);	
	return r;
}

static void __send_request(struct socket *socket, 
			  struct sockaddr_in* addr, 
			  struct inode *i_node,
			  enum clfs_type type)
{
	struct clfs_req *req;
	struct msghdr hdr;
	struct iovec *iov;
	mm_segment_t oldmm;

	req = kmalloc(sizeof(struct clfs_req), GFP_KERNEL);
	req->type = type;
	req->inode = i_node->i_ino;
	req->size = 0;
	
	iov = kmalloc(sizeof(struct iovec), GFP_KERNEL);
	iov->iov_base = req;
	iov->iov_len = sizeof(struct clfs_req);
	
	hdr.msg_name = NULL;
	hdr.msg_namelen = 0;
	hdr.msg_control = NULL;
	hdr.msg_controllen = 0;
	hdr.msg_flags = MSG_DONTWAIT;
	hdr.msg_iov = iov;
	hdr.msg_iovlen  = 1;
	
	oldmm = get_fs();
	set_fs(KERNEL_DS);
	sock_sendmsg(socket, &hdr, sizeof(struct clfs_req));
	set_fs(oldmm);
}

static void __send_response(struct socket *socket, enum clfs_status res) {
	int response = (int)res;
	struct msghdr hdr;
	struct iovec *iov;
	mm_segment_t oldmm;

	iov = kmalloc(sizeof(struct iovec), GFP_KERNEL);
	iov->iov_base = &response;
	iov->iov_len = sizeof(int);
	
	hdr.msg_name = 0;
	hdr.msg_namelen = 0;
	hdr.msg_control = NULL;
	hdr.msg_controllen = 0;
	hdr.msg_flags = MSG_DONTWAIT;
	hdr.msg_iov = iov;
	hdr.msg_iovlen  = 1;
	
	oldmm = get_fs(); 
	set_fs(KERNEL_DS);
	sock_sendmsg(socket, &hdr, sizeof(int));
	set_fs(oldmm);
}

static int __read_response(struct socket *socket) {
	int response = 0;
	struct msghdr hdr;
	struct iovec *iov;
	int len;

	iov = kmalloc(sizeof(int), GFP_KERNEL);
	iov->iov_base = &response;
	iov->iov_len = sizeof(int);
	
	hdr.msg_name = NULL;
	hdr.msg_namelen = 0;
	hdr.msg_control = NULL;
	hdr.msg_controllen = 0;
	hdr.msg_flags = MSG_DONTWAIT;
	hdr.msg_iov = iov;
	hdr.msg_iovlen  = 1;
	
	len = sock_recvmsg(socket, &hdr, sizeof(int), 0);
	if (len)
		return response;
	return CLFS_ERROR;
}

static void __send_file_data(struct socket *socket, struct inode *i_node) {
}

static int __read_file_data(struct socket *socket, struct inode *i_node) {
	return 0;
}

int ext2_evict(struct inode *i_node) {

	struct sockaddr_in *server_addr = NULL;
	struct socket *socket;
	int r = -1;

	printk(KERN_ALERT "About to evict file %lu\n", i_node->i_ino);

	r = sock_create(PF_INET, SOCK_STREAM, IPPROTO_TCP, &socket);

	printk(KERN_ALERT "Socket created, %d\n", r);

	/* memset(server_addr, 0, sizeof(struct sockaddr_in)); */
	server_addr = kmalloc(sizeof(struct sockaddr_in), GFP_KERNEL);
	if (!server_addr) {
		printk(KERN_ALERT "kmalloc error \n");
		goto evict_out;
	}

	__prepare_addr(server_addr, i_node);
	printk(KERN_ALERT "Socket addr prepared, about to connect\n");
	r = __connect_socket(socket, server_addr, i_node);
	if (r) {
		printk(KERN_ALERT "Socket connect error: %d\n", r);
		goto evict_release_out;
	}
	printk(KERN_ALERT "Socket connected, about to send request\n");
	__send_request(socket, server_addr, i_node, CLFS_PUT);
	printk(KERN_ALERT "Request sent, about to read response\n");

	r = __read_response(socket);
	if (r == CLFS_OK) {
		printk(KERN_ALERT "Got OK response, start to evict file %lu\n", i_node->i_ino);
		__send_file_data(socket, i_node);
		r = __read_response(socket);
		if (r == CLFS_OK) {
			printk(KERN_ALERT "Successfully evict file %lu\n", i_node->i_ino);			
			/* clean up local file here */
		}
	}
evict_release_out:
	sock_release(socket);
evict_out:
	return r;
}

int ext2_fetch(struct inode *i_node)
{
	struct sockaddr_in *server_addr = NULL;
	struct socket *socket;
	int r = -1;
	
	r = sock_create(PF_INET, SOCK_STREAM, IPPROTO_TCP, &socket);
	memset(server_addr, 0, sizeof(struct sockaddr_in));
	__prepare_addr(server_addr, i_node);
	r = __connect_socket(socket, server_addr, i_node);
	if (!r) {
		printk(KERN_ALERT "Socket create error: %d\n", r);
		goto evict_out;
	}

	__send_request(socket, server_addr, i_node, CLFS_GET);
	r = __read_response(socket);
	if (r == CLFS_OK) {
		r = __read_file_data(socket, i_node);
		__send_response(socket, (enum clfs_status) r);
	}
	sock_release(socket);
evict_out:
	return r;
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

static struct inode *evict_ext2_iget(struct super_block *super, long ino)
{
	struct inode *inode = ext2_iget(super, ino);

	if ((void *)inode == (void *)(-ESTALE))
		return inode;

	if (atomic_read(&inode->i_writecount) == 0)
		return inode;

	return NULL;
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

	printk(KERN_ALERT "Calling ext2_evict_fs.\n");

	if (utility < 10 * ext2_sup->water_low) {
		printk(KERN_ALERT "In ext2_evict_fs: no need to evict.\n");
		return 0;
	}

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
		node = evict_ext2_iget(super, current_inode);
		/*printk(KERN_ALERT "current_inode: %d %d %p\n", node->i_ino, node->i_count, node);*/
		if ((void *)node == (void *)(-ESTALE) || node == NULL) {
			++current_inode;

			if (current_inode > max_inode_number)
				current_inode = min_inode_number;
			continue;
		}
		mutex_lock(&node->i_mutex);
		
		if (!S_ISREG(node->i_mode) || atomic_read(&node->i_writecount) > 0) {
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
			printk(KERN_ALERT "Calling ext2_evict, i_ino: %lu, i_writecount: %d\n", node->i_ino, atomic_read(&node->i_writecount));
			res = ext2_evict(node);
			set_evicted = kmalloc(sizeof(struct evicted), GFP_KERNEL);
			set_evicted->evicted = 1;
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
