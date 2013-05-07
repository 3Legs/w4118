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
#include <linux/crypto.h>
#include <linux/swap.h>
#include <asm/uaccess.h>

#include <linux/net.h>
#include <net/sock.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/file.h>
#include <linux/socket.h>
#include <linux/smp_lock.h>

#include "ext2.h"
#include "xattr.h"
#include "acl.h"
#include "xip.h"

#define d(x) printk(KERN_ALERT "%d\n", x)
#define test_and_free(x) if(x) kfree(x)
#define SEND_SIZE 4096
#define RECV_SIZE 256

enum clfs_status {
	CLFS_OK = 0,            /* Success */
	CLFS_INVAL = EINVAL,    /* Invalid address */
	CLFS_ACCESS = EACCES,   /* Could not read/write file */
	CLFS_ERROR,             /* Other errors */
	CLFS_NEXT,              /* Next data packet please */
	CLFS_END                /* No more, please */
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

struct evict_page {
	char data[SEND_SIZE];
	int end;
};

DEFINE_MUTEX(evict_mutex);

static inline void __prepare_msghdr(struct msghdr *hdr, struct iovec * iov, void *data, size_t len, int flags) {

	iov->iov_base = data;
	iov->iov_len = len;
	
	hdr->msg_name = NULL;
	hdr->msg_namelen = 0;
	hdr->msg_control = NULL;
	hdr->msg_controllen = 0;
	hdr->msg_flags = flags;
	hdr->msg_iov = iov;
	hdr->msg_iovlen  = 1;
}

static inline void __prepare_addr(struct sockaddr_in *addr, struct inode*i) {
	addr->sin_family = AF_INET;
	addr->sin_port = htons(((struct ext2_sb_info *)i->i_sb->s_fs_info)->port);
	addr->sin_addr.s_addr = in_aton(((struct ext2_sb_info *)i->i_sb->s_fs_info)->ip);

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
	struct iovec iov;
	mm_segment_t oldmm;

	req = kmalloc(sizeof(struct clfs_req), GFP_KERNEL);
	req->type = type;
	req->inode = i_node->i_ino;
	req->size = i_node->i_size;

	
	__prepare_msghdr(&hdr, &iov, (void *) req, sizeof(struct clfs_req), MSG_DONTWAIT);
	printk(KERN_ALERT "Req size: %d, Send size %d\n", hdr.msg_iov->iov_len, sizeof(struct clfs_req));
	oldmm = get_fs();
	set_fs(KERNEL_DS);
	sock_sendmsg(socket, &hdr, sizeof(struct clfs_req));
	set_fs(oldmm);
}

static void __send_response(struct socket *socket, enum clfs_status res) {
	enum clfs_status response = res;
	struct msghdr hdr;
	struct iovec iov;
	mm_segment_t oldmm;

	__prepare_msghdr(&hdr, &iov, (void *) &response, sizeof(enum clfs_status), MSG_DONTWAIT);
	oldmm = get_fs(); 
	set_fs(KERNEL_DS);
	sock_sendmsg(socket, &hdr, sizeof(enum clfs_status));
	set_fs(oldmm);
}

static int __read_response(struct socket *socket) {
	int response = 0;
	struct msghdr hdr;
	struct iovec iov;
	int len;

	__prepare_msghdr(&hdr, &iov, (void *) &response, sizeof(int), MSG_DONTWAIT);
	
	len = sock_recvmsg(socket, &hdr, sizeof(int), 0);
	if (len)
		return response;
	return CLFS_ERROR;
}


/*
 * send file data through socket
 * 1. store the hash code of file data 
 * 2. encrypt data for safety and stored the key
 * 3. send
 * 4. handle local data (delete page cache and reclaim blocks)
 */


static int evict_page_cache_read(struct file *file, pgoff_t offset, struct inode *inode)
{
	struct address_space *mapping = inode->i_mapping;
	struct page *page; 
	int ret;

	do {
		page = page_cache_alloc_cold(mapping);
		if (!page)
			return -ENOMEM;

		ret = add_to_page_cache_lru(page, mapping, offset, GFP_KERNEL);
		if (ret == 0)
			ret = mapping->a_ops->readpage(file, page);
		else if (ret == -EEXIST)
			ret = 0; /* losing race to add is OK */

		page_cache_release(page);

	} while (ret == AOP_TRUNCATED_PAGE);
		
	return ret;
}

static inline struct page* __evict_get_page(struct inode *i_node, int i) {
	struct page *page;
	struct address_space *mapping = i_node->i_mapping;

evict_retry:
	page = find_lock_page(mapping, i);
	if (!page) {
		evict_page_cache_read(NULL, i, i_node);
		goto evict_retry;
	}
	return page;
}


static void __send_file_data_to_server(struct socket *socket, struct inode *i_node) {
	struct address_space *mapping = i_node->i_mapping;
	unsigned long nr_pages = mapping->nrpages;
	struct page *page;
	char *buf = kmalloc(SEND_SIZE, GFP_KERNEL);
	struct msghdr hdr;
	struct iovec iov;
	mm_segment_t oldmm;
	char *map;
	int i = 0;

	while (i < nr_pages) {
		/* read No.i page from mapping */
		page = read_mapping_page(mapping, i, NULL);
		++i;
		if (!page) {
			printk(KERN_ALERT "Can't get page %d\n", i);
			return;
		}

		lock_page(page);
		map = kmap(page);
		memcpy(buf, map, SEND_SIZE);

		__prepare_msghdr(&hdr, &iov, buf, SEND_SIZE, 0);
		oldmm = get_fs();
		set_fs(KERNEL_DS);
		sock_sendmsg(socket, &hdr, sizeof(struct evict_page));
		set_fs(oldmm);
		kunmap(page);
		remove_from_page_cache(page);
		page_cache_release(page);

		unlock_page(page);
	}
} 

/*
 * read file data from a socket
 * 1. decrypt the data received using the stored key
 * 2. get the hash code and check authentication
 * 3. write data to file
 */

static enum clfs_status __read_file_data_from_server(struct socket *socket, struct inode *i_node) {
	struct address_space *mapping = i_node->i_mapping;
	struct page *page;
	struct msghdr hdr;
	struct iovec iov;
	char c;
	char *map;
	int i = 0;
	int k;
	enum clfs_status r;
	unsigned long nr_pages = mapping->nrpages;
	unsigned long size = i_node->i_size;
	unsigned long len = 0, total_len = 0;

	__prepare_msghdr(&hdr, &iov, &c, sizeof(char), MSG_WAITALL);
	page = __evict_get_page(i_node, i);
	map = kmap(page);

	while (1) {
		k = sock_recvmsg(socket, &hdr, sizeof(char), MSG_WAITALL);
		if (k < 0) {
			printk(KERN_ALERT "Recv error %d\n", k);
			goto read_out;
		}
		
		memcpy(map+len, &c, 1);
		len++;
		total_len++;
		if (total_len >= size)
			goto read_out;

		if (len == SEND_SIZE) {
			len = 0;
			mark_page_accessed(page);
			kunmap(page);
			unlock_page(page);
			i++;
			page = __evict_get_page(i_node, i);
			map = kmap(page);
		}
	}
read_out:
	mark_page_accessed(page);
	kunmap(page);
	unlock_page(page);
	if (total_len != size) {
		printk(KERN_ALERT "File length error %lu, %lu\n", total_len, size);
		r = CLFS_ERROR;
	} else {
		printk(KERN_ALERT "File received success\n");
		r = CLFS_OK;
	}
	return r;
}

int ext2_evict(struct inode *i_node) {

	struct sockaddr_in *server_addr = NULL;
	struct socket *socket;
	int r = -1;
	loff_t record_size;

	printk(KERN_ALERT "About to evict file %lu\n", i_node->i_ino);

	r = sock_create(PF_INET, SOCK_STREAM, IPPROTO_TCP, &socket);

	printk(KERN_ALERT "Socket created, %d\n", r);

	server_addr = kmalloc(sizeof(struct sockaddr_in), GFP_KERNEL);
	if (!server_addr) {
		printk(KERN_ALERT "kmalloc error \n");
		goto evict_release_out;
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
		__send_file_data_to_server(socket, i_node);
		r = __read_response(socket);
		if (r == CLFS_OK) {
			printk(KERN_ALERT "Successfully evict file %lu\n", i_node->i_ino);			
			/* clean up local file here */
			record_size = i_node->i_size;
			i_size_write(i_node, 0);
			ext2_truncate(i_node);
			i_size_write(i_node, record_size);
		} else {
			printk(KERN_ALERT "Evict error %d on file %lu\n", r, i_node->i_ino);			
		}
	}

evict_release_out:
	if (socket)
		sock_release(socket);
	return r;
}

int ext2_fetch(struct inode *i_node)
{
	struct sockaddr_in *server_addr = NULL;
	struct socket *socket;
	int r;
	enum clfs_status res;

	printk(KERN_ALERT "About to fetch file: %lu\n", i_node->i_ino);
	r = sock_create(PF_INET, SOCK_STREAM, IPPROTO_TCP, &socket);
	printk(KERN_ALERT "Socket created, %d\n", r);

	server_addr = kmalloc(sizeof(struct sockaddr_in), GFP_KERNEL);
	if (!server_addr) {
		printk(KERN_ALERT "kmalloc error \n");
		r = -1;
		goto fetch_out;
	}

	__prepare_addr(server_addr, i_node);
	r = __connect_socket(socket, server_addr, i_node);

	if (r) {
		printk(KERN_ALERT "Socket create error: %d\n", r);
		r = -1;
		goto fetch_out;
	}
	printk(KERN_ALERT "Socket connected, about to send request\n");

	__send_request(socket, server_addr, i_node, CLFS_GET);
	res = __read_response(socket);
	if (res == CLFS_OK) {
		printk(KERN_ALERT "Got OK reponse, about to read file from server\n");
		res = __read_file_data_from_server(socket, i_node);
		if (res == CLFS_OK)
			printk(KERN_ALERT "Read file success!\n");
		__send_response(socket, res);
	} else if (res == CLFS_ACCESS) {
		printk(KERN_ALERT "Can't access file %lu from server\n", i_node->i_ino);	
		r = -1;
	}
	if (socket)
		sock_release(socket);
fetch_out:
	return r;
}

void evict_mutex_lock()
{
	mutex_lock(&evict_mutex);
}

void evict_mutex_unlock()
{
	mutex_unlock(&evict_mutex);
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
	struct inode *node;
	struct dentry *ext2_root = super->s_root;
	struct inode *root_inode = ext2_root->d_inode;
	struct ext2_sb_info *ext2_sup = super->s_fs_info;
	struct ext2_super_block *ext2_es = ext2_sup->s_es;

	struct timespec *scan_time = kmalloc(sizeof(struct timespec), GFP_KERNEL);
	struct timespec *set_time = kmalloc(sizeof(struct timespec), GFP_KERNEL);
	struct timespec *current_time = kmalloc(sizeof(struct timespec), GFP_KERNEL);
	struct clock_hand *clockhand = kmalloc(sizeof(struct clock_hand), GFP_KERNEL);
	struct evicted *set_evicted = kmalloc(sizeof(struct evicted), GFP_KERNEL);
	struct evicted *scan_evicted = kmalloc(sizeof(struct evicted), GFP_KERNEL);

	int used_blocks = ext2_es->s_blocks_count - ext2_count_free_blocks(super);
	int total_blocks = ext2_es->s_blocks_count;
	int utility = (used_blocks * 1000) / total_blocks;
	long min_inode_number = (long) EXT2_FIRST_INO(super);
	long max_inode_number = (long) le32_to_cpu(ext2_es->s_inodes_count);
	long current_inode;
	int res;

	printk(KERN_ALERT "Calling ext2_evict_fs.\n");

	if (utility < 10 * ext2_sup->water_low) {
		printk(KERN_ALERT "No need to evict.\n");
		res = 0;
		goto out;
	}

	mutex_lock(&root_inode->i_mutex);

	res = ext2_xattr_get(root_inode, EXT2_XATTR_INDEX_TRUSTED,
			     "clockhand", clockhand, sizeof(struct clock_hand));

	if (res < 0) {
		clockhand->hand = min_inode_number;
		current_inode = min_inode_number;

		printk(KERN_ALERT "min: %lu max: %lu\n", min_inode_number, max_inode_number);

		res = ext2_xattr_set(root_inode, EXT2_XATTR_INDEX_TRUSTED,
				     "clockhand", clockhand, sizeof(struct clock_hand), 0);
		mutex_unlock(&root_inode->i_mutex);
		if (res < 0) {
			printk(KERN_ALERT "Error in ext2_xattr_set.\n");
			goto out;
		}
	} else {
		mutex_unlock(&root_inode->i_mutex);
		current_inode = clockhand->hand;
		printk(KERN_ALERT "clock_hand: %lu\n", current_inode);
	}

	while (1) {
		node = evict_ext2_iget(super, current_inode);
		if ((void *)node == (void *)(-ESTALE) || node == NULL)
			goto continue_loop_with_no_lock;
		
		if (!S_ISREG(node->i_mode) || atomic_read(&node->i_writecount) > 0)
			goto continue_loop_with_no_lock;

		mutex_lock(&node->i_mutex);
		getnstimeofday(current_time);
		res = ext2_xattr_get(node, EXT2_XATTR_INDEX_TRUSTED,
				     "scantime", scan_time, sizeof(struct timespec));

		if (res < 0)
			scan_time->tv_sec = scan_time->tv_nsec = 0;

		set_time->tv_sec = current_time->tv_sec;
		set_time->tv_nsec = current_time->tv_nsec;

		res = ext2_xattr_set(node, EXT2_XATTR_INDEX_TRUSTED,
				     "scantime", set_time, sizeof(struct timespec), 0);
		if (res < 0) {
			mutex_unlock(&node->i_mutex);
			printk(KERN_ALERT "Error in ext2_xattr_set create.\n");
			goto out;
		}

		if (time_greater(scan_time, &node->i_atime)) {

			res = ext2_xattr_get(node, EXT2_XATTR_INDEX_TRUSTED,
					     "evicted", scan_evicted, sizeof(struct evicted));

			if (res >= 0 && scan_evicted->evicted == 1)
				goto continue_loop;

			printk(KERN_ALERT "Calling ext2_evict, i_ino: %lu, i_writecount: %d free_blocks: %lu\n", 
				node->i_ino, atomic_read(&node->i_writecount), ext2_count_free_blocks(super));

			res = ext2_evict(node);
			if (!res) {
				set_evicted->evicted = 1;
				res = ext2_xattr_set(node, EXT2_XATTR_INDEX_TRUSTED,
						     "evicted", set_evicted, sizeof(struct evicted), 0);
				if (res < 0) {
					mutex_unlock(&node->i_mutex);
					printk(KERN_ALERT "Error in ext2_xattr_set.\n");
					goto out;
				}
			}

			ext2_sup = super->s_fs_info;
			ext2_es = ext2_sup->s_es;
			used_blocks = ext2_es->s_blocks_count - ext2_count_free_blocks(super);
			/* used_blocks = ext2_es->s_blocks_count - super */
			utility = (used_blocks * 1000) / total_blocks;

			printk(KERN_ALERT "utility after ext2_evict: %d free_blocks: %lu\n", utility, ext2_count_free_blocks(super));

			if (utility < 10 * ext2_sup->evict) {
				clockhand->hand = current_inode;
				res = ext2_xattr_set(root_inode, EXT2_XATTR_INDEX_TRUSTED,
						     "clockhand", clockhand, sizeof(struct clock_hand), 0);
				if (res < 0)
					printk(KERN_ALERT "Error in ext2_xattr_set replace.\n");
				
				printk(KERN_ALERT "ext2_evict_fs return.\n");
				mutex_unlock(&node->i_mutex);
				goto out;
			}
		} 
	continue_loop:
		mutex_unlock(&node->i_mutex);
	continue_loop_with_no_lock:
		++current_inode;
		if (current_inode > max_inode_number)
			current_inode = min_inode_number;
		continue;
	}
out:
	test_and_free(scan_time);
	test_and_free(set_time);
	test_and_free(current_time);
	test_and_free(clockhand);
	test_and_free(set_evicted);
	test_and_free(scan_evicted);
	return res;
}
