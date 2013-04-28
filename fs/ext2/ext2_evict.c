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

int ext2_evict(struct inode *i_node);

/* Fetch the file specified by i_node from the cloud server.
* The function should allocate space for the file on the local
* filesystem. No other metadata of the file should be changed.
* Lock the inode appropriately to prevent concurrent fetch
* operations on the same inode, and return appropriate errors.
*/

int ext2_fetch(struct inode *i_node);

int ext2_evict_fs(struct super_block *super);