#include "predator.h"
#include "session.h"
using namespace std;
#include "common.h"
using namespace __session_namespace;

void usage(const char*);
session *Session=NULL; 
static void onInt(int signo)
{
	if(Session)
		delete Session;
}
int main(int argc,char *argv[])
{
    int opt;
    char dev[8];
    string addrs[16];
    int addrCnt=0;

    signal(SIGINT,onInt);//temp
    while((opt=getopt(argc,argv,"i:"))!=EOF)
    {
	switch(opt)
	{
	case('i'):
	    strlcpy(dev,optarg,sizeof(dev));
	    break;
	default:
	    usage(argv[0]);
	}
    }
    
    for(int i=optind;i<argc;i++,addrCnt++)
    {
	if(argv[i])
	    addrs[addrCnt]=argv[i];
    }
        
    try
    {
	Session	= new session(addrs,addrCnt,dev);
	Session->Launch();
	pause();
    }    
    catch(PredException &exc)
    {
	printf("%s",exc.what());
       	return -1;
    }
    
    return 0;
}

void usage(const char* exec)
{
    fprintf(stderr,"Usage: %s [-i interface] [targets_list]\n",exec);
    fprintf(stderr,"Example: %s -i rl0 192.168.0.1 192.168.0.2 192.168.0.254\n",exec);
}

void init_daemon()
{
    /*struct rlimit limit;
    pid_t pid;
    int fd[3];

    umask(0);    
   
    if(getrlimit(RLIMIT_NOFILE,&limit)<0)
        throw PredException("getrlimit()",errno);
    
    if((pid=fork())<0)
        throw PredException("fork()",errno);
    else if (pid) // parent
        exit(0);

    setsid(); //open a new process session without a controlling tty
    
    
    if(chdir("/")<0) //Our daemon will be (usually) run under chroot() jail
	throw PredException("chdir()",errno);

    
    if (limit.rlim_max==RLIM_INFINITY)
        limit.rlim_max=1024;
    for(u_int32_t i=0;i<limit.rlim_max;i++)
        close(i);
    
    if((*fd=open("/dev/null",O_RDWR))<0)
	throw("open()",errno);
    *(fd+1)=dup(*fd);
    *(fd+2)=dup(*fd);
    
    if (*fd!=0 || *(fd+1)!=1 || *(fd+2)!=2) {
        throw PredException(L"General",L"unexpected descriptors");
    }
    openlog("predator", LOG_CONS, LOG_DAEMON);
    
    //ensure only one instance of our daemon, otherwise exit
    //TODO
    /*int LockFile;
    if((LockFile=open("/var/run/predator.pid",O_RDWR|O_CREAT,S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH))<0)
	throw PredException(L"open()",errno);
    if(flock(LockFile,LOCK_NB)<0 && errno==EWOULDBLOCK)
	throw PredException("General","Another instance is running");
    ftruncate(LockFile, 0);
    char buf[32];
    sprintf(buf, "%ld", (long)getpid());
    write(LockFile, buf, strlen(buf)+1);*/
}
