#ifndef __COMMON_H
#define __COMMON_H

#include "predator.h"


namespace __session_namespace{

const u_int32_t PoisonDelay=15;//sec
const int pcapTimeout=1000;//msec
const size_t arpRetries=5;
const size_t snapMax=65535;
const u_int8_t hwAddrLen=ETHER_ADDR_LEN, //MAC length
	                  prAddrLen=4; //protocol (IPv4) address lengt
const u_int8_t hwAddrStrLen=18;
const u_int8_t ethHdrLen=LIBNET_ETH_H,
    arpHdrLen=LIBNET_ARP_H+20,
    ipHdrLen=LIBNET_IPV4_H;
const u_int8_t hwBroadcast[hwAddrLen]=
    {0xff,0xff,0xff,0xff,0xff,0xff}; //broadcast MAC

typedef libnet_ethernet_hdr ethernet_hdr;
typedef libnet_ipv4_hdr ipv4_hdr;

struct arp_hdr
{
	u_int16_t ar_hrd __attribute__((packed));
	u_int16_t ar_pro __attribute__((packed));
	u_int8_t ar_hln __attribute__((packed));
	u_int8_t ar_pln __attribute__((packed));
	u_int16_t ar_op __attribute__((packed));
	u_int8_t ar_sha[6] __attribute__((packed));
	in_addr_t ar_spa;
	u_int8_t ar_tha[6] __attribute__((packed));
	in_addr_t ar_tpa;
} __attribute__((packed)); //that f*cking alignment... don't know what to do, really



void BuildEtherArp(u_int16_t arpOp,
		   u_int8_t *shwAddr,
		   in_addr_t *sprAddr,
		   u_int8_t *dhwAddr,
		   in_addr_t *dprAddr,
		   libnet_t *link);

typedef void (*pcap_handler)(void*,const struct pcap_pkthdr*,const u_int8_t*);
int pcap_loop(pcap_t *pcap,
	      int cnt,
	      pcap_handler routine,
	      void *user);//my version of pcap_loop()

void CleanerMutex(void *mutex);
void CleanerPcap(void *pcap);
void CleanerPcapDump(void *pcapDump);

class target //specifies a single target
{
public:
    target():m_hwAddrStr(new char[hwAddrStrLen]){}
    ~target(){if(m_hwAddrStr) delete[] m_hwAddrStr;}
    target(const sockaddr_in &prAddr,const u_int8_t *hwAddr);
    target(const target &src);
    target(in_addr_t prAddr,const u_int8_t *hwAddr);
    
    sockaddr_in m_prAddr;//protocol(IPv4)
    u_int8_t m_hwAddr[hwAddrLen];//hardware(MAC)
    target& operator=(const target &src) throw();

    int operator==(const target &targ) const throw();
    int operator==(in_addr_t prAddr) const throw();
    int operator==(const u_int8_t *hwAddr) const throw();
    operator char*() const throw();
private:
    char *m_hwAddrStr;
};

struct if_info
{
    char m_name[8];//canonical *nix iface name(eth0,fxp0,tun1...) can't be longer
    u_int8_t m_hwAddr[hwAddrLen];//MAC; only ethernet interfaces
    in_addr_t m_prAddr;//protocol address in network(big endian) byte order
    int m_immed;
};

struct packet //for libnet_adv*
{
    u_int8_t *m_packet;
    u_int32_t m_packet_s;
};
extern if_info ifInfo; 
}

#endif //__COMMON_H
