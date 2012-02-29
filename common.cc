#include "common.h"

__session_namespace::if_info __session_namespace::ifInfo;

void __session_namespace::BuildEtherArp(u_int16_t arpOp,u_int8_t *shwAddr,in_addr_t *sprAddr,u_int8_t *dhwAddr,in_addr_t *dprAddr,libnet_t *link)
{
    libnet_ptag_t ptag=LIBNET_PTAG_INITIALIZER;
    
    ptag=libnet_build_arp(ARPHRD_ETHER,                           
			  ETHERTYPE_IP,                           
			  hwAddrLen,                              
			  prAddrLen,                              
			  arpOp,                          
			  shwAddr,
			  reinterpret_cast<u_int8_t*>(sprAddr),
			  dhwAddr,
			  reinterpret_cast<u_int8_t*>(dprAddr),
			  NULL,
			  0,
			  link,
			  0);
    
    if(ptag<0)
	throw PredException(libnet_geterror(link));
    
    ptag=libnet_build_ethernet(dhwAddr,
			       shwAddr,
			       ETHERTYPE_ARP,
			       NULL,
			       0,
			       link,
			       0);
    if(ptag<0)
	throw PredException(libnet_geterror(link));
}

int __session_namespace::pcap_loop(pcap_t *pcap,
	      int cnt,
	      pcap_handler routine,
	      void *user)
{
    int pcapFd=pcap_fileno(pcap);
    fd_set rset;
    pcap_pkthdr hdr;
    FD_ZERO(&rset);
    for(int i=0;i<cnt||cnt<0;i++)
    {
	FD_SET(pcapFd,&rset);
	if(select(pcapFd,&rset,NULL,NULL,NULL)<0)
	    return -1;
	const u_int8_t *packet=pcap_next(pcap,&hdr);
	if(!packet){i--;
		continue;}
	routine(user,&hdr,packet);
    }
}

void __session_namespace::CleanerPcap(void *pcap)
{
    if(pcap)
       pcap_close(reinterpret_cast<pcap_t*>(pcap));
}

void __session_namespace::CleanerPcapDump(void *pcapDump)
{
    if(pcapDump)
       pcap_dump_close(reinterpret_cast<pcap_dumper_t*>(pcapDump));
}

void __session_namespace::CleanerMutex(void *mutex)
{
    if(pthread_mutex_unlock(reinterpret_cast<pthread_mutex_t*>(mutex))!=EINVAL)
	pthread_mutex_destroy(reinterpret_cast<pthread_mutex_t*>(mutex));
}


__session_namespace::target::target(in_addr_t prAddr,const u_int8_t *hwAddr):m_hwAddrStr(new char[hwAddrStrLen])
{
    bzero(&m_prAddr,sizeof(m_prAddr));
    m_prAddr.sin_addr.s_addr=prAddr;
    m_prAddr.sin_family=AF_INET;
    m_prAddr.sin_len=sizeof(m_prAddr);
    memcpy(m_hwAddr,hwAddr,hwAddrLen);

    snprintf(m_hwAddrStr,hwAddrStrLen,
	     "%02hX:%02hX:%02hX:%02hX:%02hX:%02hX",
	     m_hwAddr[0],
	     m_hwAddr[1],
	     m_hwAddr[2],
	     m_hwAddr[3],
	     m_hwAddr[4],
	     m_hwAddr[5]);
}
__session_namespace::target::target(const sockaddr_in &prAddr,const u_int8_t *hwAddr):m_hwAddrStr(new char[hwAddrStrLen])
{
    memcpy(&m_prAddr,&prAddr,sizeof(prAddr));
    memcpy(m_hwAddr,hwAddr,hwAddrLen);
    snprintf(m_hwAddrStr,hwAddrStrLen,
	     "%02hX:%02hX:%02hX:%02hX:%02hX:%02hX",
	     m_hwAddr[0],
	     m_hwAddr[1],
	     m_hwAddr[2],
	     m_hwAddr[3],
	     m_hwAddr[4],
	     m_hwAddr[5]);
}

__session_namespace::target::target(const target &src):m_hwAddrStr(new char[hwAddrStrLen])
{
    memcpy(&m_prAddr,&src.m_prAddr,sizeof(sockaddr_in));
    memcpy(m_hwAddr,src.m_hwAddr,hwAddrLen);

    strlcpy(m_hwAddrStr,src.m_hwAddrStr,hwAddrStrLen);
}

__session_namespace::target& __session_namespace::target::operator=(const target &src) throw()
{
    memcpy(&m_prAddr,&src.m_prAddr,sizeof(sockaddr_in));
    memcpy(m_hwAddr,src.m_hwAddr,hwAddrLen);
	m_hwAddrStr=new char[hwAddrStrLen];
    strlcpy(m_hwAddrStr,src.m_hwAddrStr,hwAddrStrLen);
    return *this;
}

int __session_namespace::target::operator==(const target &targ) const throw()
{
    if(!memcmp(m_hwAddr,targ.m_hwAddr,hwAddrLen)) 
	return (targ.m_prAddr.sin_addr.s_addr==m_prAddr.sin_addr.s_addr);
}

int __session_namespace::target::operator==(in_addr_t prAddr) const throw()
{ 
    return (m_prAddr.sin_addr.s_addr==prAddr);
}

int __session_namespace::target::operator==(const u_int8_t *hwAddr) const throw()
{
    return (!memcmp(m_hwAddr,hwAddr,hwAddrLen)); 
}	
__session_namespace::target::operator char*() const throw()
{
    return m_hwAddrStr;
}
