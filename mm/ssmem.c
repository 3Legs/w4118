#include <linux/syscalls.h>
#include <linux/cred.h>
#include <asm/uaccess.h>
#include <asm/unistd.h>

/* macro define */
#define SSMEM_MAX 1024
#define SSMEM_FLAG_CREATE   0x1
#define SSMEM_FLAG_WRITE    0x2
#define SSMEM_FLAG_EXEC     0x4

/* structures define */
struct ssmem_struct {
   int id;
};

SYSCALL_DEFINE3(ssmem_attach, int, id, int, flags, size_t, length) {
	return 0;
}


SYSCALL_DEFINE1(ssmem_detach, void*, addr) {
	return 0;
}
