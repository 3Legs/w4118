#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <dirent.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>

#define __NR_get_colors 251
#define PROC_NUMBER 200

struct bind {
	int pid;
	char *cmdname;
	int flag;
};

void get_bind_list(struct bind *);
int parse_int(char *);
int get_num(int);
int total = 0;

int main(int argc, char **argv) {
	int i,j;
	struct bind *bind_list;
	int nr_pids;
	pid_t *pids;
	u_int16_t *colors;
	int *retval;
	int result;
	if(argc <= 1) {
		printf("Too few arguments!\n");
		exit(0);
	}
	bind_list = malloc(sizeof(struct bind)*PROC_NUMBER);
	memset(bind_list, 0, sizeof(struct bind)*PROC_NUMBER);
	for(i=0;i<PROC_NUMBER;++i) {
		bind_list[i].pid = -1;
	}
	get_bind_list(bind_list);
	nr_pids = argc-1;
	pids = malloc(sizeof(pid_t)*nr_pids);
	memset(pids,0,sizeof(pid_t)*nr_pids);
	colors = malloc(sizeof(u_int16_t)*nr_pids);
	memset(colors,0,sizeof(u_int16_t)*nr_pids);
	retval = malloc(sizeof(int)*nr_pids);
	memset(retval,0,sizeof(int)*nr_pids);

	for(i=0;i<nr_pids;++i) {
		for(j=0;j<PROC_NUMBER;++j) {
			if(bind_list[j].cmdname == NULL) {
				continue;
			}
			if(strcmp(bind_list[j].cmdname, argv[i+1])==0 && bind_list[j].flag == 0) {
				pids[i] = bind_list[j].pid;
				bind_list[j].flag = 1;
				break;
			}
		}
	}

	result = syscall(__NR_get_colors, nr_pids, pids, colors, retval);
 	for(i=0;i<nr_pids;++i) {
		if(retval[i]!=-22) {
			printf("pid: %d     color: %d     retval: %d\n", pids[i], colors[i], retval[i]);
		}
 	}
 	for(i=0;i<nr_pids;++i) {
		if(retval[i]==-22) {
			fprintf(stderr, "Failed to get the color of thread %s!\n", argv[i+1]);
		}
 	}
	return result;
}

int get_num(int i)
{
	int ret = 1;
	int p;
	for(p=0;p<i;++p) {
		ret*=10;
	}
	return ret;
}

int parse_int(char *name)
{
	int len = strlen(name);
	int ret = 0;
	int i;
	for(i=0;i<len;++i) {
		if(name[i]<48||name[i]>57) {
			return -1;
		}
	}
	for(i=0;i<len;++i) {
		ret += (int)(name[i]-48)*get_num(len-i-1);
	}
	return ret;
}

void get_bind_list(struct bind *bl)
{
	int count = 0;
	int i;
	char ch;
	FILE *fp = NULL;
	struct dirent *de;
	char buf[1024];
	DIR *dir = NULL;
	struct stat *s = malloc(sizeof(struct stat));
	
	if(lstat("/proc", s)<0) {
		printf("lstat error!\n");
		exit(0);
	}

	if(chdir("/proc")<0) {
		printf("change directory to /proc failed!\n");
		exit(0);
	}

	dir = opendir("/proc");
	while((de = readdir(dir)) != NULL) {
		if(de->d_name[0] == '.') {
			continue;
		}
		if(lstat(de->d_name, s)<0) {
			printf("lstat error!\n");
			exit(0);
		}
		if(S_ISDIR(s->st_mode)) {
			chdir(de->d_name);
			memset(buf,0,1024);
			if(access("cmdline", R_OK)!=0) {
				chdir("..");
				continue;
			}
			fp = fopen("cmdline", "r");
			i=0;
			while(ch=fgetc(fp)) {
				if(ch == EOF || ch == ' ' || ch == '\0') {
					break;
				}
				buf[i] = ch;
				++i;
			}
			fclose(fp);
			bl[count].cmdname = malloc(sizeof(char)*(1+strlen(buf)));
			memset(bl[count].cmdname, 0, sizeof(char)*(1+strlen(buf)));
			strcpy(bl[count].cmdname, buf);
			if(parse_int(de->d_name)!=-1) {
				bl[count].pid = parse_int(de->d_name);
			}
			else {
				continue;
			}
			++count;
			++total;
			chdir("..");
		}
	}
	/*
	for(i=0;i<PROC_NUMBER;++i) {
		printf("%s %d ", bl[i].cmdname,bl[i].pid);
	}
	*/
}
