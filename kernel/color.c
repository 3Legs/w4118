#include <linux/sched.h>
#include <linux/syscalls.h>
#include <linux/cred.h>

#include <asm/uaccess.h>
#include <asm/unistd.h>

/* Syscall number 223. nr_pids contains the number of entries in
   the pids, colors, and the retval arrays. The colors array contains the
   color to assign to each pid from the corresponding position of
   the pids array. Returns 0 if all set color requests
   succeed. Otherwise, The array retval contains per-request
   error codes -EINVAL for an invalid pid, or 0 on success. 
*/
SYSCALL_DEFINE4(set_colors, int, nr_pids, pid_t *, pids, u_int16_t *, colors, int *,retval){

  int flag = 0;
  int i = nr_pids;
  int error_code;

  pid_t iter_pid;
  u_int16_t iter_color;

  struct task_struct *iter_task;
  struct task_struct *iter_thread;
  struct task_struct *group_leader;

  /* check user privilege */
  if (current_euid() != 0){
    return -EACCES;
  }

  while (--i >= 0){
    /* verify each pid_t's pointer */
    if (copy_from_user(&iter_pid, (pids+i), sizeof(pid_t)))
      return -EFAULT;
    /* verify corresponding color pointer */
    if (copy_from_user(&iter_color, (colors+i), sizeof(u_int16_t)))
      return -EFAULT;

    /* try to get task by pid */
    rcu_read_lock();
    iter_task = find_task_by_vpid(iter_pid);
    rcu_read_unlock();

    if (iter_task){
      get_task_struct(iter_task);
      iter_task->color = iter_color;
      put_task_struct(iter_task);
      /* set color to all thread */
      rcu_read_lock();
      group_leader = find_task_by_vpid(iter_task->tgid);
      iter_thread = group_leader;
      do {
        get_task_struct(iter_thread);
        iter_thread->color = iter_color;
        put_task_struct(iter_thread);
      }while_each_thread(group_leader,iter_thread);
      rcu_read_unlock();
      error_code = 0;
    }
    else{
      flag = -EINVAL;
      error_code = -EINVAL;
    }
    if(copy_to_user((retval+i),&error_code,sizeof(int)))
      return -EFAULT; 
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
  int error_code;

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
      if (copy_to_user((colors+i), &(iter_task->color), sizeof(u_int16_t))){ 
        put_task_struct(iter_task);
        return -EFAULT;
      }
      put_task_struct(iter_task);
      error_code = 0;
    }
    else{
      flag = -EINVAL;
      error_code = -EINVAL;
    }
    if(copy_to_user((retval+i),&error_code,sizeof(int)))
      return -EFAULT; 
  }
  return flag;
}
