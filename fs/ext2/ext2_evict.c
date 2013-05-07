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
	
	iov = kmalloc(sizeof(struct iovec), GFP_KERNEL);
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

static enum clfs_status __read_response(struct socket *socket) {
	enum clfs_status response = CLFS_OK;
	struct msghdr hdr;
	struct iovec iov;
	int len;

	__prepare_msghdr(&hdr, &iov, (void *) &response,
			 sizeof(enum clfs_status), MSG_WAITALL);
	
	len = sock_recvmsg(socket, &hdr,
			   sizeof(enum clfs_status), MSG_WAITALL);
	if (len == sizeof(enum clfs_status))
		return response;
	else
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

static void __send_file_data_to_server(struct socket *socket, struct inode *i_node) {
	struct address_space *mapping = i_node->i_mapping;
	struct page *page;
	struct msghdr hdr;
	struct iovec iov;
	mm_segment_t oldmm;
	struct evict_page *epage = kmalloc(sizeof(struct evict_page),
					   GFP_KERNEL);
	int nr_pages;
	char *map;
	int i;
	enum clfs_status response;

	/* get total number of pages of the given file*/
	/*TODO: we may not want hard-code it*/
	nr_pages = (i_node->i_size / SEND_SIZE) + 1;
	for (i = 0; i < nr_pages; ++i) {

		memset(epage, 0, sizeof(struct evict_page));

		page = read_mapping_page(mapping, i, NULL);
		lock_page(page);
		map = kmap(page);
		memcpy(epage->data, map, SEND_SIZE);
		epage->end = 0;

		/* if last, we need to notify server */
		if (i == (nr_pages - 1)) {
			epage->end = (i_node->i_size) - (i_node->i_size / SEND_SIZE) * SEND_SIZE;
		}

		__prepare_msghdr(&hdr, &iov, epage, sizeof(struct evict_page), MSG_DONTWAIT);
		oldmm = get_fs();
		set_fs(KERNEL_DS);
		sock_sendmsg(socket, &hdr, sizeof(struct evict_page));
		set_fs(oldmm);
		kunmap(page);
		remove_from_page_cache(page);
		page_cache_release(page);

		unlock_page(page);

		/* if not last, we need to sync by reading a response*/
		response = __read_response(socket);
		if (response == CLFS_END) {
			printk(KERN_ALERT "All pages sent, %d in total\n", i);
			return;
		}

	}
} 

/*
 * read file data from a socket
 * 1. decrypt the data received using the stored key
 * 2. get the hash code and check authentication
 * 3. write data to file
 */

static int __read_file_data_from_server(struct socket *socket, struct inode *i_node) {
	struct address_space *mapping = i_node->i_mapping;
	struct page *page;
	struct msghdr hdr;
	struct iovec iov;
	struct evict_page *epage = kmalloc(sizeof(struct evict_page),
					   GFP_KERNEL);
	int nr_pages;
	char *map;
	int i = 0;
	int r;
	int len, buflen, total_len = 0;

	nr_pages = (i_node->i_size / SEND_SIZE) + 1;
	while (1) {

		if (i > nr_pages + 1) {
			printk(KERN_ALERT "Page number overflow %d\n", i);
			r = CLFS_ERROR;
			goto read_out_with_no_lock;
		}


		__prepare_msghdr(&hdr, &iov, epage, sizeof(struct evict_page), MSG_WAITALL);
		len = sock_recvmsg(socket, &hdr, sizeof(struct evict_page), MSG_WAITALL);

		if (len < sizeof(struct evict_page)) {
			printk(KERN_ALERT "Receving error\n");
			r = CLFS_ERROR;
			__send_response(socket, CLFS_END);
			goto read_out_with_no_lock;
			
		}

		printk(KERN_ALERT "Receive page %d with end: %d\n", i, epage->end);

		if (epage->end == -1) { /* with zero buffer*/
			__send_response(socket, CLFS_END);
			goto read_out_regular_out;
		}

		if (epage->end < 0) {
			printk(KERN_ALERT "Something went wrong here\n");
			r = CLFS_ERROR;
			__send_response(socket, CLFS_END);
			goto read_out_with_no_lock;
		}


		if (epage->end) {
			buflen = epage->end;
			__send_response(socket, CLFS_END);
		} else {
			buflen = SEND_SIZE;
			__send_response(socket, CLFS_NEXT);

		}
		
evict_retry:
		page = find_lock_page(mapping, i);
		if (!page) {
			/* printk(KERN_ALERT "Can't find page\n"); */
			/* r =  -ENOMEM; */
			evict_page_cache_read(NULL, i, i_node);
			goto evict_retry;
		}

		/* lock_page(page); */
		map = kmap(page);

		memcpy(map, epage->data, buflen); 
		total_len += buflen;

		mark_page_accessed(page);
		kunmap(page);
		unlock_page(page);

		/* if last, we are done */
		if (epage->end) {
			goto read_out_regular_out;
		}
		printk(KERN_ALERT "ready to receive page %d\n", i+1);
		++i;
	}
read_out_regular_out:
	r = CLFS_OK;
	if (total_len != i_node->i_size) {
		printk(KERN_ALERT "File length error\n");
		r = CLFS_ERROR;
	}
read_out_with_no_lock:
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
			/* printk(KERN_ALERT "access: %lu %lu\n", i_node->i_atime.tv_sec, i_node->i_atime.tv_nsec); */
			i_size_write(i_node, 0);
			ext2_truncate(i_node);
			i_size_write(i_node, record_size);
			/* printk(KERN_ALERT "access: %lu %lu\n", i_node->i_atime.tv_sec, i_node->i_atime.tv_nsec); */
		} else {
			printk(KERN_ALERT "Evict error %d on file %lu\n", r, i_node->i_ino);			
		}
	}

evict_release_out:
	if (socket)
		sock_release(socket);
	printk(KERN_ALERT "Evict Page size: %d\n", (int)sizeof(struct evict_page));
	return r;
}

int ext2_fetch(struct inode *i_node)
{
	struct sockaddr_in *server_addr = NULL;
	struct socket *socket;
	int r;

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
	r = __read_response(socket);
	if (r == CLFS_OK) {
		printk(KERN_ALERT "Got OK reponse, about to read file from server\n");
		r = __read_file_data_from_server(socket, i_node);
		if (r == CLFS_OK) {
			/* __read_file_data_from_server() will check the validity of file*/
			printk(KERN_ALERT "Read file success!\n");
		}
		__send_response(socket, (enum clfs_status) r);			
	} else if (r == CLFS_ACCESS) {
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
