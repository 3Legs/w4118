
#define SSMEM_MAX 1024

#define SSMEM_FLAG_CREATE   0x1
#define SSMEM_FLAG_WRITE    0x2
#define SSMEM_FLAG_EXEC     0x4

  /* Syscall 333. Map an existing ssmem segment identified by
   * id (0..SSMEM_MAX-1) into the caller's address space. The flags
   * argument is a bitmask containing one or more of
   * SSMEM_FLAG_CREATE, SSMEM_FLAG_WRITE, and SSMEM_FLAG_EXEC.    
   * If the ssmem segment does not exist and SSMEM_FLAG_CREATE
   * is specified, a new ssmem segment must be created at that id.
   * The length field is only valid when creating a new ssmem segment,
   * and specifies its length in bytes. The flags argument specifies
   * the access permissions (writable/executable) with which the ssmem
   * segment is to be mapped into the caller's address space. These
   * permissions may be different for each process that maps the
   * segment.
   *
   * On success, return a pointer to the ssmem segment. On failure,
   * return (void*)-ENOMEM if the memory cannot be allocated, -EINVAL
   * if the supplied id or length is invalid, and -EADDRNOTAVAIL if
   * an ssmem segment at a particular id doesn't exist and
   * SSMEM_CREATE is not specified. 
   */

SYSCALL_DEFINE3(ssmem_attach, int, id, int, flags, size_t, length) {
}

  /* Syscall 334. Unmap a shared memory segment mapped at the
   * address specified in the addr argument. If the current process
   * is the last one mapping the ssmem segment, the segment should
   * be destroyed and the id released.
   *
   * Return 0 on success, and -EFAULT if the addr is invalid or
   * does not point to a ssmem segment.
   */
SYSCALL_DEFINE1(ssmem_detach, void*, addr) {
}
