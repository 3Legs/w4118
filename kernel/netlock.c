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
	pid_t pid;
	struct list_head list;
};

struct my_timer {
	pid_t pid;
	struct timer_list *timer;
	struct list_head list;
};

/* Syscall 333. Acquire netlock. type indicates
   whether a use or sleep lock is needed, and the timeout_val indicates
   how long a user is willing to wait in seconds. It's value is
   ignored for sleepers. Returns 0 on success and -1 on failure.  
*/

atomic_t first_timeout = ATOMIC_INIT(0);
atomic_t radio_controller = ATOMIC_INIT(0);
struct user user_pids = {
	.pid = 0,
	.list = LIST_HEAD_INIT(user_pids.list),
};
struct list_head *user_list = &(user_pids.list);

struct my_timer my_timer_list = {
	.pid = 0,
	.timer = NULL,
	.list = LIST_HEAD_INIT(my_timer_list.list),
};
struct list_head *my_timer_head = &(my_timer_list.list);

DEFINE_SPINLOCK(user_pids_lock);

static DECLARE_RWSEM(netlock);
static DECLARE_WAIT_QUEUE_HEAD(first);

static void wake_net_sleeper(unsigned long data)
{
	if(atomic_read(&first_timeout) == 0) {
		printk(KERN_ALERT "Timer %d in waker not first \n", (int)data);
		return;
	}
	else {
		printk(KERN_ALERT "Timer %d in waker is first \n", (int)data);
		atomic_set(&first_timeout, 0);
		wake_up(&first);
	}
}

SYSCALL_DEFINE2(net_lock, netlock_t, type, u_int16_t, timeout_val) {
	int ret = 0;
	if(type == NET_LOCK_USE) {
		struct user *temp;
		struct my_timer *timer_node;
		//ret = sched_setscheduler_edf(current, deadline);
		temp = kmalloc(sizeof(struct user), GFP_KERNEL);
		if(!temp) {
			printk(KERN_ALERT "Error in kmalloc!\n");
			return -ENOMEM;
		}
		temp->pid = current->pid;

		timer_node = kmalloc(sizeof(struct my_timer), GFP_KERNEL);
		if(!timer_node) {
			printk(KERN_ALERT "Error in kmalloc!\n");
			return -ENOMEM;
		}
		timer_node->pid = current->pid;
		timer_node->timer = kmalloc(sizeof(struct timer_list), GFP_KERNEL);
		if(!timer_node->timer) {
			printk(KERN_ALERT "Error in kmalloc!\n");
			return -ENOMEM;
		}
		init_timer(timer_node->timer);
		timer_node->timer->expires = jiffies + timeout_val*HZ;
		timer_node->timer->data = (unsigned long)(current->pid);
		timer_node->timer->function = wake_net_sleeper;
		add_timer(timer_node->timer);
		list_add(&(timer_node->list), my_timer_head);

		down_read(&netlock);
		list_add(&(temp->list), user_list);
		printk(KERN_ALERT "User called net_lock success, PID: %d\n", temp->pid);
		goto suc;
	}
	else if(type == NET_LOCK_SLEEP) {
		if(atomic_read(&radio_controller) != 0 && atomic_read(&radio_controller) != current->pid) {
			printk(KERN_ALERT "There can only be one radio controller whose PID is: %d. The request from PID: %d is illegal!\n", atomic_read(&radio_controller), current->pid);
			goto err;
		}
		else {
			down_write(&netlock);
			atomic_set(&radio_controller, current->pid);
			printk(KERN_ALERT "Radio controller called net_lock success, PID: %d!\n", atomic_read(&radio_controller));
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
	if(atomic_read(&radio_controller) == current->pid) {
		up_write(&netlock);
		printk(KERN_ALERT "Radio controller called net_unlock success, PID: %d!\n", atomic_read(&radio_controller));
		goto suc;
	}

	spin_lock(&user_pids_lock);

	list_for_each_entry_safe(cur, next, user_list, list) {
		if(cur->pid == current->pid) {
			up_read(&netlock);
			//sched_setscheduler_edf(current, 0);
			list_del(&(cur->list));
			printk(KERN_ALERT "In list_for_each_entry_safe, deleting PID: %d!\n", cur->pid);
			flag = 1;
			goto label0;
		}
	}

label0:
	spin_unlock(&user_pids_lock);

	if(!flag) {
		printk(KERN_ALERT "Unknown process %d tried to call net_unlock, abort!\n", current->pid);
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
	struct my_timer *cur;
	struct my_timer *next;
	int ret = 0;
	if(atomic_read(&radio_controller) != current->pid) {
		printk(KERN_ALERT "The PID of the radio controller is %d, the current pid %d is not allowed to call net_lock_wait_timeout!\n", atomic_read(&radio_controller), current->pid);
		ret = -EPERM;
		goto err;
	}
	atomic_set(&first_timeout, 1);
	wait_event(first, atomic_read(&first_timeout) == 0);

	list_for_each_entry_safe(cur, next, my_timer_head, list) {
		del_timer_sync(cur->timer);
		if(cur->pid!=0) {
			list_del(&(cur->list));
		}
	}
suc:
	return 0;
err:
	return ret;
}