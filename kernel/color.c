#include <linux/kernel_stat.h>
#include <linux/module.h>
#include <linux/interrupt.h>
#include <linux/percpu.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/swap.h>
#include <linux/pid_namespace.h>
#include <linux/notifier.h>
#include <linux/thread_info.h>
#include <linux/time.h>
#include <linux/jiffies.h>
#include <linux/posix-timers.h>
#include <linux/cpu.h>
#include <linux/syscalls.h>
#include <linux/delay.h>
#include <linux/tick.h>
#include <linux/kallsyms.h>
#include <linux/cred.h>

#include <asm/uaccess.h>
#include <asm/unistd.h>
#include <asm/div64.h>
#include <asm/timex.h>
#include <asm/io.h>


/* Syscall number 223. nr_pids contains the number of entries in
   the pids, colors, and the retval arrays. The colors array contains the
   color to assign to each pid from the corresponding position of
   the pids array. Returns 0 if all set color requests
   succeed. Otherwise, The array retval contains per-request
   error codes -EINVAL for an invalid pid, or 0 on success. 
*/
SYSCALL_DEFINE4(set_colors, int, nr_pids, pid_t *, pids, u_int16_t *, colors, int *,retval){

  /* check user privilege */
  if (current_euid() != 0){
    return -EACCES;
  }

  int flag = 0;
  int i = nr_pids;
  
  pid_t iter_pid;
  u_int16_t iter_color;
  struct task_struct *iter_task;

  while (--i >= 0){
    /* verify each pid_t's pointer */
    if (copy_from_user(&iter_pid, (pids+i), sizeof(pid_t)))
      return -EFAULT;
    /* verify corresponding color pointer */
    if (copy_from_user(&iter_color, (colors+i), sizeof(u_int16_t)))
      return -EFAULT;

    /* try to get task by pid */
    rcu_read_lock();
    iter_task = pid_task(find_vpid(iter_pid),PIDTYPE_PID);
    rcu_read_unlock();
    if (iter_task){
      get_task_struct(iter_task);
      iter_task->color = iter_color;
    }
    else{
      retval[i] = -EINVAL;
      flag = -EINVAL;
      continue;
    }
  }
  return flag;
}


/* Syscall number 251. Gets the colors of the processes
   contained in the pids array. Returns 0 if all set color requests
   succeed. Otherwise, an error code is returned. The array
   retval contains per-request error codes: -EINVAL for an
   invalid pid, or 0 on success.
*/
SYSCALL_DEFINE4(get_colors, int, nr_pids, pid_t *, pids, u_int16_t *, colors, int *, retval){
  int flag = 0;
  int i = nr_pids;
  pid_t iter_pid;
  struct task_struct *iter_task;
  while (--i >= 0){
    /* verify each pid_t's pointer */
    if (copy_from_user(&iter_pid, (pids+i), sizeof(pid_t)))
      return -EFAULT;
    /* try to get task by pid */
    /* start lock */
    rcu_read_lock();
    iter_task = find_task_by_vpid(iter_pid);
    rcu_read_unlock();
    if (iter_task){
      get_task_struct(iter_task);
      /* copy task->color to color array */
      if (copy_to_user((colors+i), &(iter_task->color), sizeof(u_int16_t))){ return -EFAULT;}
      retval[i] = 0;
    }
    else{
      retval[i] = -EINVAL;
      flag = -EINVAL;
      continue;
    }
  }
  return flag;
}
