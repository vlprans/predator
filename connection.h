#ifndef __CONNECTION_H
#define __CONNECTION_H

#include "predator.h"
#include "common.h"

//implementation of connection class that handles individual 'connections'
namespace __session_namespace{
class connection
{
public:
    connection(const target &t1,
	       const target &t2,
	       libnet_t *link,
	       pthread_mutex_t &linkMutex);
    connection(const connection &conn);
    ~connection();
    connection& operator=(const connection &conn);
    int DoIt(const char *filter=NULL,
	     int doSpoofing=1,
	     int doRouting=1) throw();

    int operator==(const connection &conn) const throw();
    int IsEqual(const target &t1,const target &t2) const throw();
    
    const target* GetPeers()const throw(){return m_peers;}

    int Dump(const char *filter=NULL,//separate filter for dumping
	      const char *file=NULL,
	      size_t snaplen=snapMax);
private:
    static void *StartSpoofing(void *conn);
    static void *StartRouting(void *conn);

    static void ProcessPacket(void *conn,
			      const struct pcap_pkthdr *pcapHdr,
			      const u_int8_t *packet);//pcap callback routine
    static void CleanerSpoof(void *conn);
    void Spoofer() throw(PredException);
    void Router() throw(PredException);

    void RebuildPackets() throw(PredException);
    void BuildEtherArp(u_int16_t arpOp,u_int8_t *shwAddr,in_addr_t *sprAddr,u_int8_t *dhwAddr,in_addr_t *dprAddr) throw(PredException);
    void Normalize() throw(PredException);//repair target's arp caches
    

private:
    target m_peers[2];//communicating machines
    packet m_packets[2];//forged replies
    
    pthread_t m_spooferThread,m_routerThread;
    pthread_mutex_t m_spooferLock,m_routerLock;

    libnet_t *m_link;
    pthread_mutex_t &m_linkMutex;
    
    pcap_t *m_pcapRouter,*m_pcapDumper;
    pcap_dumper_t *m_pcapDumpFile;//unused;
    int m_dumpFd;

    std::string m_dumperFilter,m_routerFilter;// filters for routing and dumping
    std::string m_dumpFile;//file to dump to
    size_t m_dumpSnaplen;//how many bytes to dump

    char *m_PcapErr;
private:
    static const int routeSnaplen=snapMax;//max snaplen 
};


}

#endif //__CONNECTION_H
