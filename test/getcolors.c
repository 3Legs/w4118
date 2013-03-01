#include <stdio.h>
#include <linux/unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>

#define __NR_get_colors 251
/* __syscall4(long,get_colors,int, nr_pids,pid_t*, pids,u_int16_t*, colors, int*, retval); */

int main(int argc, char** argv){
  int nr_pids = 1;
  pid_t *pids = malloc(sizeof(pid_t) * nr_pids);
  u_int16_t *colors = malloc(sizeof(int) * nr_pids);
  int *retval = malloc(sizeof(int) * nr_pids);
  pids[0] = (pid_t)1;
  
  int result = syscall(__NR_get_colors,nr_pids,pids,colors,retval);
  printf("Result: %d, Color: %d\n",result,colors[0]);
  return 0;
}
