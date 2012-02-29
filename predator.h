
/*Common includes, externs, consts, globals...*/ 
#ifndef __PREDATOR_H
#define __PREDATOR_H

#ifdef HAVE_CONFIG_H
   #include <config.h>
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <syslog.h>
#include <stdarg.h>
#include <cerrno>
#include <unistd.h>
#include <cstdlib>
#include <csignal>
#include <ctime>
#include <sys/resource.h>
#include <pthread.h>

#include <exception>
#include <string>
#include <iostream>

#include<pcap.h>
#include<libnet.h>
/*#ifndef bzero
#define bzero(buf,len) memset(buf,0,len)
#endif*/

extern int opterr;
extern int optind;
extern char* optarg;

class PredException //basic exception class, quick and dirty;
{
public:
    PredException(){}
    explicit PredException(std::string func,int code,int IsCritical=0):
	m_IsCritical(IsCritical),m_msg("") 
    {
	char err[_POSIX2_LINE_MAX];
	strerror_r(code,err,sizeof(err));
	m_msg=func+": "+err+"\n";
    }
    explicit PredException(std::string func,std::string descr,int IsCritical=0):
	m_IsCritical(IsCritical),m_msg("") 
    {
	m_msg=func+": "+descr+"\n";
    }
    explicit PredException(std::string descr,int IsCritical=0):
	m_IsCritical(IsCritical),m_msg(descr){}
    explicit PredException(const char* descr,int IsCritical=0):
	m_IsCritical(IsCritical),m_msg(descr){}
    
    virtual const char* what() const throw(){
	return m_msg.c_str();
    }
    int IsCritical() const throw(){
	return m_IsCritical;
    }
    
protected:
    std::string m_msg;
    int m_IsCritical;
};

void init_daemon();

#endif //__PREDATOR_H

