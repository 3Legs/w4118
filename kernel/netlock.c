#include <linux/sched.h>
#include <linux/syscalls.h>
#include <linux/cred.h>

#include <asm/uaccess.h>
#include <asm/unistd.h>

/* Syscall 333. Acquire netlock. type indicates
   whether a use or sleep lock is needed, and the timeout_val indicates
   how long a user is willing to wait in seconds. It's value is
   ignored for sleepers. Returns 0 on success and -1 on failure.  
*/

SYSCALL_DEFINE2(net_lock, netlock_t, type, u_int16_t, timeout_val) {

}

/* Syscall 334. Release netlock.Return 0
   on success and -1 on failure.  
*/
SYSCALL_DEFINE0(net_unlock) {

}

/* Syscall 335. Wait for user timeout. Return 0 on a successful
   timeout, and -<Corresponding ERRNO> on failure.  
*/
SYSCALL_DEFINE0(net_lock_wait_timeout) {

}