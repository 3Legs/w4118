#include <linux/sched.h>
#include <linux/syscalls.h>
#include <linux/spinlock.h>
#include <linux/cred.h>
#include <linux/rwsem.h>
#include <linux/list.h>
#include <linux/wait.h>
#include <asm/uaccess.h>
#include <asm/unistd.h>

/*
	Which pids are holding the reader lock.
	The syscall net_unlock use this structure to
	determine who is calling net_unlock. The net_unlock
	syscall does not have arguments.
*/

struct user {
	/* The pid of a user who owns a read lock. */
	pid_t pid;
	struct list_head list;
};

/*
When a user calls net_lock, it initialize a my_timer instance,
the first timer is responsible for waking up the radio controller
who is waiting in net_lock_wait_timeout, other timers are canceled
afterwards.
*/

struct my_timer {
	/* The user PID */
	pid_t pid;
	/* The timer to wake up the radio controller */
	struct timer_list *timer;
	struct list_head list;
};

/* Syscall 333. Acquire netlock. type indicates
   whether a use or sleep lock is needed, and the timeout_val indicates
   how long a user is willing to wait in seconds. It's value is
   ignored for sleepers. Returns 0 on success and -1 on failure.
*/

/* first_timeout is used to indicate whether the first user has timed out */
atomic_t first_timeout = ATOMIC_INIT(0);
/*
The PID of the radio controller. It is initialized to 0, the first sleeper who
calls net_lock is recognized as the legal radio controller. Other processes 
afterwards are considered illegal radio controller.
*/
atomic_t radio_controller = ATOMIC_INIT(0);
/* Initialize a list to record the users that holds the net_lock */
struct user user_pids = {
	.pid = 0,
	.list = LIST_HEAD_INIT(user_pids.list),
};
struct list_head *user_list = &(user_pids.list);
/*
Initialize a list of timers to try to wait up the radio controller upon timeout.
When the radio controller is waken up, it will destroy all remaining timers.
*/
struct my_timer my_timer_list = {
	.pid = 0,
	.timer = NULL,
	.list = LIST_HEAD_INIT(my_timer_list.list),
};
struct list_head *my_timer_head = &(my_timer_list.list);
/* A spinlock to protect the list of the users that hold the net_lock */
DEFINE_SPINLOCK(user_pids_lock);
/* A read-write semaphore to act as the net_lock */
static DECLARE_RWSEM(netlock);
/* The sleeper should wait on this wait queue to wait for the first user timeout */
static DECLARE_WAIT_QUEUE_HEAD(first);
/* The call-back function of the timers */
static void wake_net_sleeper(unsigned long data)
{
	if (atomic_read(&first_timeout) == 0) {
		/* Not first timeout user */
		printk(KERN_ALERT "Timer %d in waker not first \n", (int)data);
		return;
	} else {
		/* The first timeout user */
		printk(KERN_ALERT "Timer %d in waker is first \n", (int)data);
		/* Set first_timeout to 0 so that the sleeper is waken up */
		atomic_set(&first_timeout, 0);
		/* Try to wake up the radio controller */
		wake_up(&first);
	}
}

SYSCALL_DEFINE2(net_lock, netlock_t, type, u_int16_t, timeout_val) {
	int ret = 0;
	if (timeout_val <= 0) {
		printk(KERN_ALERT "Timeout value must be a positive number!\n");
		ret = -EINVAL;
		goto err;
	}
	if (type == NET_LOCK_USE) {/* The user calls net_lock */
		/* record the user pid */
		struct user *temp;
		/* set up a timer to wake up the radio controller */
		struct my_timer *timer_node;
		temp = kmalloc(sizeof(struct user), GFP_KERNEL);
		if (!temp) {
			printk(KERN_ALERT "Error in kmalloc!\n");
			ret = -ENOMEM;
			goto err;
		}
		temp->pid = current->pid;
		timer_node = kmalloc(sizeof(struct my_timer), GFP_KERNEL);
		if (!timer_node) {
			printk(KERN_ALERT "Error in kmalloc!\n");
			ret = -ENOMEM;
			goto err;
		}
		timer_node->pid = current->pid;
		timer_node->timer = kmalloc(sizeof(struct timer_list), GFP_KERNEL);
		if (!timer_node->timer) {
			printk(KERN_ALERT "Error in kmalloc!\n");
			ret = -ENOMEM;
			goto err;
		}
		init_timer(timer_node->timer);
		/* Set the policy of the user to EDF policy and the key value is the timeout value */
		ret = sched_setscheduler_edf(current, timeout_val*HZ+jiffies);
		/* Set the timer expires value to the timeout value */
		timer_node->timer->expires = jiffies + timeout_val*HZ;
		/*
		Set the argument of the timer call back function to the current PID of the user.
		The timer call back function has no process context, so we have to pass the pid as
		an argument to debug
		*/
		timer_node->timer->data = (unsigned long)(current->pid);
		/* Set the call back function */
		timer_node->timer->function = wake_net_sleeper;
		/* Activate the timer */
		add_timer(timer_node->timer);
		/* Add the timer to the list, we have to retain a handle of the timers */
		list_add(&(timer_node->list), my_timer_head);
		/* Acquire the net_lock */
		down_read(&netlock);
		/* Add the user pid to the list */
		list_add(&(temp->list), user_list);
		printk(KERN_ALERT "User called net_lock success, PID: %d\n", temp->pid);
		goto suc;
	} else if (type == NET_LOCK_SLEEP) {/* The sleeper calls the net_lock */
		if (atomic_read(&radio_controller) != 0 && atomic_read(&radio_controller) != current->pid) {
			/* There can only be one radio controller in the system, so only the first process is considered as a valid radio controller */
			printk(KERN_ALERT "There can only be one radio controller whose PID is: %d. The request from PID: %d is illegal!\n", atomic_read(&radio_controller), current->pid);
			goto err;
		} else {
			/* Acquire the writer lock */
			down_write(&netlock);
			/* Set the radio_controller value to its pid, so it becomes the only valid radio controller in the system. */
			atomic_set(&radio_controller, current->pid);
			printk(KERN_ALERT "Radio controller called net_lock success, PID: %d!\n", atomic_read(&radio_controller));
			goto suc;
		}
	} else {
		printk(KERN_ALERT "The type argument can only be NET_LOCK_SLEEP or NET_LOCK_USE!\n");
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
	if (atomic_read(&radio_controller) == current->pid) {
		/* radio controller calls net_unlock */
		up_write(&netlock);
		printk(KERN_ALERT "Radio controller called net_unlock success, PID: %d!\n", atomic_read(&radio_controller));
		goto suc;
	}

	spin_lock(&user_pids_lock);

	/* 
	Search through the list, if there is a PID in the list that
	has the same PID as the current PID. Then the PID is a user.
	*/
	list_for_each_entry_safe(cur, next, user_list, list) {
		if (cur->pid == current->pid) {
			/* The user release the lock */
			up_read(&netlock);
			/* Set the policy to normal process */
			sched_setscheduler_edf(current, 0);
			/* Delete the user PID from the list */
			list_del(&(cur->list));
			printk(KERN_ALERT "In list_for_each_entry_safe, deleting PID: %d!\n", cur->pid);
			flag = 1;
			goto label0;
		}
	}
label0:
	spin_unlock(&user_pids_lock);
	if (!flag) {
		printk(KERN_ALERT "Unknown process %d tried to call net_unlock, abort!\n", current->pid);
		goto err;
	} else {
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
	/* There must be a registered radio controller before using net_lock_wait_timeout. */
	if (atomic_read(&radio_controller) == 0) {
		printk(KERN_ALERT "No radio controller registered, cannot use net_lock_wait_timeout!\n");
		ret = -EACCES;
		goto err;
	}
	/* Only one radio controller is permited */
	if (atomic_read(&radio_controller) != current->pid) {
		printk(KERN_ALERT "The PID of the radio controller is %d, the current 
			pid %d is not allowed to call net_lock_wait_timeout!\n", atomic_read(&radio_controller), current->pid);
		ret = -EPERM;
		goto err;
	}
	/* Set first_timeout to 1 and then wait on the variable to become 0 */
	atomic_set(&first_timeout, 1);
	/* The radio controller should wait for the first_timeout */
	wait_event(first, atomic_read(&first_timeout) == 0);

	list_for_each_entry_safe(cur, next, my_timer_head, list) {
		/* Delete all remaining timers when the first timer times out */
		del_timer_sync(cur->timer);
		if (cur->pid!=0) {
			list_del(&(cur->list));
		}
	}
	return 0;
err:
	return ret;
}
