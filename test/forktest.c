#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <dirent.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#define MAX 200

struct bind {
	int pid;
	char *cmdname;
};

struct ft {
	int delay;
	int type;/* 0 for fork, 1 for vfork, 2 for clone*/
	char *cmd;
	char **args;
	char **cmdline;
	int arglen;
};

void get_bind_list(struct bind *);
int parse_int(char *);
int get_num(int);
void parser(int, char **, int *);
void parse_cmd(struct ft *, int, char **);
void show_cmd(struct ft *);

int total = 0;

int main(int argc, char **argv)
{
	struct ft *cmd = malloc(sizeof(struct ft));
	parse_cmd(cmd, argc, argv);
	fprintf(stdout, "pid %d: sleeping...\n", getpid());
	sleep(cmd->delay);
	fprintf(stdout, "pid %d: wake up...\n", getpid());
	pid_t pid;
	if(cmd->type==0||cmd->type==2) {
		fprintf(stdout, "pid %d: call fork()\n", getpid());
		pid = fork();
	}
	else {
		fprintf(stdout, "pid %d: call vfork()\n", getpid());
		pid = vfork();
	}
	if(pid<0) {
		fprintf(stderr, "Error in fork or vfork!\n");
		exit(0);
	}
	if(pid == 0) {
		/*
		if(strcmp(cmd->cmd, "forktest")==0) {
			fprintf(stdout, "pid %d: call forktest...\n", getpid());
			execvp("./forktest", cmd->cmdline);
		}
		else if(strcmp(cmd->cmd, "getcolors")==0) {
			fprintf(stdout, "pid %d: call getcolors...\n", getpid());
			execvp("./getcolors", cmd->cmdline);
		}
		else if(strcmp(cmd->cmd, "setcolors")==0) {
			fprintf(stdout, "pid %d: call setcolors...\n", getpid());
			execvp("./setcolors", cmd->cmdline);
		}
		
		else {
			fprintf(stdout, "pid %d: call %s\n", getpid(), cmd->cmd);
			execvp(cmd->cmd, cmd->cmdline);
		}
		* */
		fprintf(stdout, "pid %d: call %s\n", getpid(), cmd->cmd);
		execvp(cmd->cmd, cmd->cmdline);
	}
	else {
		waitpid(pid, NULL, 0);
	}
}

void show_cmd(struct ft *cmd)
{
	int i;
	printf("DELAY: %d\n", cmd->delay);
	printf("TYPE: %d\n", cmd->type);
	printf("CMD: %s\n", cmd->cmd);
	printf("ARG: ");
	for(i=0;i<cmd->arglen;++i) {
		printf("%s ", cmd->args[i]);
	}
	printf("\n");
}

void parse_cmd(struct ft *cmd, int argc, char **argv)
{
	if(argc<4) {
		fprintf(stderr, "To few arguments!\n");
		exit(0);
	}
	cmd->delay = parse_int(argv[1]);
	if(strcmp(argv[2], "fork")==0) {
		cmd->type = 0;
	}
	else if(strcmp(argv[2], "vfork")==0) {
		cmd->type = 1;
	}
	else if(strcmp(argv[2], "clone")==0) {
		cmd->type = 2;
	}
	else {
		fprintf(stderr, "Illegal cmdline!\n");
		exit(0);
	}
	cmd->cmd = argv[3];
	cmd->cmdline = (argv+3);
	if(argc>4) {
		cmd->args = (argv+4);
		cmd->arglen = argc-4;
	}
	else {
		cmd->args = NULL;
		cmd->arglen = 0;
	}
}

void parser(int number, char **procs, int *pids) 
{
	int i,j;
	struct bind *bind_list;
	int nr_pids;
	bind_list = malloc(sizeof(struct bind)*MAX);
	memset(bind_list, 0, sizeof(struct bind)*MAX);
	for(i=0;i<MAX;++i) {
		bind_list[i].pid = -1;
	}
	get_bind_list(bind_list);
	nr_pids = number;

	for(i=0;i<nr_pids;++i) {
		for(j=0;j<MAX;++j) {
			if(bind_list[j].cmdname == NULL) {
				continue;
			}
			if(strcmp(bind_list[j].cmdname, procs[i])==0) {
				pids[i] = bind_list[j].pid;
				break;
			}
		}
	}
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
}
