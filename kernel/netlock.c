#include <linux/sched.h>
#include <linux/syscalls.h>
#include <linux/cred.h>
#include <linux/rwsem.h>

#include <asm/uaccess.h>
#include <asm/unistd.h>

/* Syscall 333. Acquire netlock. type indicates
   whether a use or sleep lock is needed, and the timeout_val indicates
   how long a user is willing to wait in seconds. It's value is
   ignored for sleepers. Returns 0 on success and -1 on failure.  
*/

   
atomic_t sleep_hold = ATOMIC_INIT(0);
atomic_t sleep_block = ATOMIC_INIT(0);
atomic_t user_hold = ATOMIC_INIT(0);
atomic_t user_block = ATOMIC_INIT(0);


SYSCALL_DEFINE2(net_lock, netlock_t, type, u_int16_t, timeout_val) {
	netlock_t user_sleeper;
	u_int16_t declare_time;

	if(copy_from_user(&user_sleeper, &type, sizeof(netlock_t))) {
		printk("Error copy_from_user!\n");
		return -EINVAL; 
	}

	if(copy_from_user(&declare_time, &timeout_val, sizeof(u_int16_t))) {
		printk("Error copy_from_user!\n");
		return -EINVAL;
	}

	if(type == NET_LOCK_USE) {
		atomic_inc(&user_hold);
		printk("user_hold: %d\n", atomic_read(&user_hold));
	}
	else if(type == NET_LOCK_SLEEP) {
		atomic_inc(&sleep_hold);
		printk("sleep_hold: %d\n", atomic_read(&sleep_hold));
	}
	else {
		return -EINVAL;	
	}
	return NULL;
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