#include <linux/sched.h>
#include <linux/syscalls.h>
#include <linux/spinlock.h>
#include <linux/cred.h>
#include <linux/rwsem.h>
#include <linux/list.h>
#include <linux/wait.h>

#include <asm/uaccess.h>
#include <asm/unistd.h>

struct user {
	int pid;
	struct list_head list;
};

/* Syscall 333. Acquire netlock. type indicates
   whether a use or sleep lock is needed, and the timeout_val indicates
   how long a user is willing to wait in seconds. It's value is
   ignored for sleepers. Returns 0 on success and -1 on failure.  
*/

atomic_t first_timeout = ATOMIC_INIT(0);

atomic_t sleeper_pid = ATOMIC_INIT(0);
struct user user_pids = {
	.pid = 0,
	.list = LIST_HEAD_INIT(user_pids.list),
};
struct list_head *user_list = &(user_pids.list);
DEFINE_SPINLOCK(user_pids_lock);

static DECLARE_RWSEM(netlock);
static DECLARE_WAIT_QUEUE_HEAD(first);

static void wake_net_sleeper(unsigned long data)
{
	if(atomic_read(&first_timeout) != 0) {
		return;
	}
	else {
		atomic_set(&first_timeout, 1);
		wake_up(&first);
	}
}

SYSCALL_DEFINE2(net_lock, netlock_t, type, u_int16_t, timeout_val) {
	netlock_t user_sleeper = type;
	u_int16_t declare_time = timeout_val;
	int ret;
	struct timer_list timer;

	if(type == NET_LOCK_USE) {
		struct user *temp;
		down_read(&netlock);
		temp = kmalloc(sizeof(struct user), GFP_KERNEL);
		if(!temp) {
			printk(KERN_ALERT "Error in kmalloc!\n");
			return -ENOMEM;
		}
		temp->pid = current->pid;
		list_add(&(temp->list), user_list);
		init_timer(&timer);
		timer.expires = jiffies+declare_time*HZ;
		timer.data = 0;
		timer.function = wake_net_sleeper;
		add_timer(&timer);
		printk(KERN_ALERT "User call net_lock success, pid: %d!\n", temp->pid);
		goto suc;
	}
	else if(type == NET_LOCK_SLEEP) {
		if(atomic_read(&sleeper_pid) != 0) {/* If this is a sleeper holding the lock, the syscall returns. */
			printk(KERN_ALERT "There is already a sleeper, pid: %d the request is from pid: %d\n", atomic_read(&sleeper_pid), current->pid);
			goto err;
		}
		else {
			down_write(&netlock);
			atomic_set(&sleeper_pid, current->pid);
			printk(KERN_ALERT "Sleeper call net_lock success, pid: %d!\n", atomic_read(&sleeper_pid));
			goto suc;
		}
	}
	else {
		ret = -EINVAL;
		goto err;	
	}
suc:
	return 0;
err:
	return -1;
}

/* Syscall 334. Release netlock.Return 0
   on success and -1 on failure.
*/

SYSCALL_DEFINE0(net_unlock) {
	struct user *cur;
	struct user *next;
	int flag = 0;
	if(atomic_read(&sleeper_pid) == current->pid) {
		up_write(&netlock);
		printk(KERN_ALERT "Sleeper call net_unlock success, pid: %d!\n", atomic_read(&sleeper_pid));
		atomic_set(&sleeper_pid, 0);
		goto suc;
	}

	spin_lock(&user_pids_lock);

	list_for_each_entry_safe(cur, next, user_list, list) {
		if(cur->pid == current->pid) {
			printk(KERN_ALERT "In list_for_each_entry_safe, deleting pid: %d!\n", cur->pid);
			up_write(&netlock);
			list_del(&(cur->list));
			flag = 1;
			goto label0;
		}
	}

label0:
	spin_unlock(&user_pids_lock);

	if(!flag) {
		printk(KERN_ALERT "Error in net_unlock\n");
		goto err;
	}
	else {
		goto suc;
	}
	
suc:
	return 0;
err:
	return -1;
}

/* Syscall 335. Wait for user timeout. Return 0 on a successful
   timeout, and -<Corresponding ERRNO> on failure.  
*/

SYSCALL_DEFINE0(net_lock_wait_timeout) {
	atomic_set(&first_timeout, 0);
	wait_event(first, atomic_read(first_timeout));
	return 0;
}