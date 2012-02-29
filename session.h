#ifndef __SESSION_H
#define __SESSION_H

#include "predator.h"
#include "common.h"
#include "connection.h"
#include <list>
#include <vector>


namespace __session_namespace{


class session
{
public:
    class connectionInfo
    {
    public:
	connectionInfo(u_int32_t index,const target &peer1,const target &peer2):m_index(index)
	{
	    m_peers[0]=peer1;
	    m_peers[1]=peer2;
	}
	connectionInfo(u_int32_t index,const target *peers):m_index(index)
	{
	    m_peers[0]=peers[0];
	    m_peers[1]=peers[1];
	}
	u_int32_t index() const throw()
	    {return m_index;}
	const target* peers() const throw()
	    {return m_peers;}
	void peerAddr(char *addrs[2]) const throw()
	    {strlcpy(addrs[0],m_peers[0],hwAddrStrLen);
	     strlcpy(addrs[1],m_peers[1],hwAddrStrLen);}
    private:
	u_int32_t m_index;
	target m_peers[2];
	u_int32_t m_state;//unused by now;
    public://states consts will be there('established', 'unknown', etc.)
	
    };

public:
    //session();
    session(const std::string *addrs,//addrs of interest
	    size_t num,
	    const char *device=NULL,
	    int immed=1);
    ~session();

    int Launch() throw();//get everything done!
    void SpoofConnection(const target &peer1,const target &peer2) throw();
    u_int32_t GetConnectionCount() const throw();
    connectionInfo& GetConnectionInfo(u_int32_t index) const throw(); 
    int DumpConnection(u_int32_t index,
		       const char *filter=NULL,
		       const char *file=NULL,
		       size_t snaplen=snapMax) const throw(PredException);
			 
private:
    const int m_immedDev;
    libnet_t *m_link;//libnet descr.
    pthread_mutex_t m_linkMutex;
    char *m_LnetErr,//libnet error msgs.
	 *m_PcapErr; //pcap errors
    
    pthread_t m_processorThread;
    pthread_mutex_t m_processorLock;//assuring only one instance of spoofer

    std::list<target> m_Targets;
    int m_IsSpecific;
    std::vector<connection*> m_Connections;
    std::vector<connectionInfo*> m_connInfo;
private://initializers
    void EnumTargets(const std::string *addrs,size_t num) throw(PredException,std::exception);
    void InitIface(const char *device,int immed) throw(PredException);
    void UpdateConnections(const target &peer1,const target &peer2) throw(); 
private://generic private methods 
    void Processor() throw(PredException);//detects new 'connections'
private://some support routines
    int GetHwAddr(in_addr_t prAddr,u_int8_t *hwAddr) throw();//return -1 on error, 0 if ok;
    void BuildEtherArp(u_int16_t arpOp,
		       u_int8_t *shwAddr,
		       in_addr_t *sprAddr,
		       u_int8_t *dhwAddr,
		       in_addr_t *dprAddr) throw(PredException);//wrapper for common routine
    
    static void ProcessPacket(void *sess,
			      const struct pcap_pkthdr *pcapHdr,
			      const u_int8_t *);//pcap callback routine
private://thread 'engines'
    static void *StartSession(void *sess);

};

}
#endif // __SESSION_H
