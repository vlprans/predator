#include "session.h"
//implementation of session class

using __session_namespace::session;

session::session(const std::string *addrs,
		 size_t num,
		 const char *device,
		 int immed):m_immedDev(immed),
			    m_link(NULL),
			    m_linkMutex(PTHREAD_MUTEX_INITIALIZER),
			    m_processorLock(PTHREAD_MUTEX_INITIALIZER),
			    m_LnetErr(new char[LIBNET_ERRBUF_SIZE]),
			    m_PcapErr(new char[PCAP_ERRBUF_SIZE])
						 
						
{
    //libnet initialization
    m_link=libnet_init(LIBNET_LINK_ADV,const_cast<char*>(device),m_LnetErr);
    if(!m_link)
	throw PredException(m_LnetErr);
    
    
    InitIface(device,immed); //initialize interface
    if(num){//whether to build a list of 'interesting' hosts
	EnumTargets(addrs,num); //build a list of targets
	m_IsSpecific=1;
    }
    else m_IsSpecific=0;
}

session::~session()
{
    
    printf("Deleting session.\n");//debug
    for(std::vector<connection*>::iterator i=m_Connections.begin();i!=m_Connections.end();i++)
	delete *i;
    for(std::vector<connectionInfo*>::iterator i=m_connInfo.begin();i!=m_connInfo.end();i++)
	delete *i;

    if(m_link)
	libnet_destroy(m_link);
    if(m_LnetErr)
	delete[] m_LnetErr; 
    if(m_PcapErr)
	delete[] m_PcapErr;
}

int session::Launch() throw()
{
    int err=pthread_create(&m_processorThread,NULL,StartSession,this); //start the whole thing
    return err;
}

void session::SpoofConnection(const target &peer1,const target &peer2) throw()
{
    UpdateConnections(peer1,peer2);//forcibly add a 'connection'
}


u_int32_t session::GetConnectionCount() const throw()
{
    return m_Connections.size();
}

session::connectionInfo& session::GetConnectionInfo(u_int32_t index) const throw()
{
    return *m_connInfo[index];
}

//support routines

void session::InitIface(const char *device,int immed) throw(PredException)
{
    //filling in fields of ifInfo
   char *dev_tmp=reinterpret_cast<char*>(libnet_getdevice(m_link)),*err_tmp;
   if(!dev_tmp){
       if((err_tmp=libnet_geterror(m_link)))
	   throw PredException(err_tmp);
       //else //device name undefined?
   }
   else strlcpy(ifInfo.m_name,dev_tmp,10);

   libnet_ether_addr *addr_tmp=libnet_get_hwaddr(m_link);
   if(!addr_tmp)
      throw PredException(libnet_geterror(m_link));
   memcpy(&ifInfo.m_hwAddr,addr_tmp,sizeof(libnet_ether_addr));

   if((ifInfo.m_prAddr=libnet_get_ipaddr4(m_link))<0)
       throw PredException(libnet_geterror(m_link));

   //unnecesary (maybe) ioctl() to set immediate iface mode; may be removed
   ifInfo.m_immed=immed;
   ioctl(libnet_getfd(m_link),BIOCIMMEDIATE,&ifInfo.m_immed);
}

void session::EnumTargets(const std::string *addrs,size_t num) throw(PredException,std::exception)
{
   sockaddr_in prAddr;
   u_int8_t hwAddr[hwAddrLen];
   bzero(&prAddr,sizeof(prAddr));
   
   prAddr.sin_len=sizeof(sockaddr_in);
   prAddr.sin_family=AF_INET;
   
   for(size_t i=0;i<num;i++)
   {
       if((prAddr.sin_addr.s_addr=libnet_name2addr4(m_link,const_cast<char*>(addrs[i].c_str()),LIBNET_RESOLVE))<0)
	   throw PredException(libnet_geterror(m_link));
       if(GetHwAddr(prAddr.sin_addr.s_addr,hwAddr)<0)//does arp request
	   continue;
       m_Targets.push_back(target(prAddr,hwAddr));
   }
}


void *session::StartSession(void *sess)//thread engine
{
    session *Session=reinterpret_cast<session*>(sess);
    try
    {
	Session->Processor();
    }
    catch(PredException &exc)
    {
	PredException *status=new PredException(exc);
	return reinterpret_cast<void*>(status);	
    }
}

void session::UpdateConnections(const target &peer1,const target &peer2) throw()
{
    std::vector<connection*>::iterator i;
    for(i=m_Connections.begin();i!=m_Connections.end();i++)
    {
	if((*i)->IsEqual(peer1,peer2))
	    return;
    }
    i=m_Connections.insert(m_Connections.end(),
			   new connection(peer1,peer2,m_link,m_linkMutex));
    (*i)->DoIt();
	(*i)->Dump();
    m_connInfo.insert(m_connInfo.end(),
		      new connectionInfo(m_connInfo.size()-1,peer1,peer2));
}

//actual code

void session::Processor() throw(PredException)
{   //NOTE: expected to run in a separate thread; only ONE instance;.
    int error=0;
    pthread_mutexattr_t processorMutexAttr;
    if((error=pthread_mutexattr_init(&processorMutexAttr)))
	throw PredException("pthread_mutexattr_init()",error);
    if((error=pthread_mutexattr_settype(&processorMutexAttr,PTHREAD_MUTEX_ERRORCHECK)))
	throw PredException("pthread_mutexattr_settype()",error);
    if((error=pthread_mutex_init(&m_processorLock,&processorMutexAttr)))
	throw PredException("pthread_mutex_init()",error);
    pthread_mutexattr_destroy(&processorMutexAttr);
    
    if((error=pthread_mutex_lock(&m_processorLock)))
	throw PredException("pthread_mutex_lock()",error);
    pcap_t *pcap=NULL;
    pthread_cleanup_push(CleanerMutex,&m_processorLock);
    
    //wait for ARPOP_* to or from our targets and process it
    if(!(pcap=pcap_open_live(ifInfo.m_name,ethHdrLen+arpHdrLen,1,pcapTimeout,m_PcapErr)))
	throw PredException(m_PcapErr);
    pthread_cleanup_push(CleanerPcap,pcap);
    ioctl(pcap_fileno(pcap),BIOCIMMEDIATE,&m_immedDev);
	    
    char pfilter[]="arp"; //we're interested only in arp
    bpf_program fp; 
    if(pcap_compile(pcap,&fp,pfilter,1,0x0)<0)
	throw PredException(pcap_geterr(pcap));
    if(pcap_setfilter(pcap,&fp)<0)
	throw PredException(pcap_geterr(pcap));
    pcap_freecode(&fp);
    
    if(__session_namespace::pcap_loop(pcap,-1,ProcessPacket,reinterpret_cast<u_int8_t*>(this))<0)
	throw PredException(pcap_geterr(pcap));
        
} 

void session::ProcessPacket(void *sess,const struct pcap_pkthdr *pcapHdr,const u_int8_t *packet)
{

    session *Session=reinterpret_cast<session*>(sess);
    ethernet_hdr *ethHdr;
    arp_hdr *arpHdr;

    reinterpret_cast<u_int8_t*>(ethHdr)=packet;
    reinterpret_cast<u_int8_t*>(arpHdr)=packet+ethHdrLen;
    if(Session->m_IsSpecific&&arpHdr->ar_op==htons(ARPOP_REQUEST))
    {
	std::list<target>::iterator j;
	for(j=Session->m_Targets.begin();j!=Session->m_Targets.end();j++)
	{
	    if(*j==ethHdr->ether_dhost || 
	       *j==ethHdr->ether_shost)
		break;
	}
	if(j==Session->m_Targets.end())//does not fit our terms
	    return;
    }
		
    printf("A packet!!!\n");//debug
    fflush(stdout);
    //TODO: properly handle replies and requests
    
    if(arpHdr->ar_op==htons(ARPOP_REQUEST) && 
       memcmp(ethHdr->ether_shost,ifInfo.m_hwAddr,hwAddrLen)) //it shouldn't be our request
    {   
        //assume it a new 'connection'
	printf("It is a request!\n");//debug
	in_addr_t prAddr_tmp=*(reinterpret_cast<in_addr_t*>(reinterpret_cast<u_int8_t*>(arpHdr)+0x18));
	u_int8_t hwDst[hwAddrLen];
	if(Session->GetHwAddr(prAddr_tmp,hwDst)<0)
	    return;
	if(!memcmp(hwDst,ethHdr->ether_shost,hwAddrLen))
	    return;//if on the same host...

	target t2(prAddr_tmp,hwDst);
	prAddr_tmp=*(reinterpret_cast<in_addr_t*>(reinterpret_cast<u_int8_t*>(arpHdr)+0xE));//struct alignment does some weird things, so we have to do it manually
	target t1(prAddr_tmp,ethHdr->ether_shost);//source host; all required information is available;
	
	
	Session->UpdateConnections(t1,t2);
    }
}


int session::GetHwAddr(in_addr_t prAddr,u_int8_t *hwAddr) throw()
{
    pcap_t *pcap;
    if(!(pcap=pcap_open_live(ifInfo.m_name,ethHdrLen+arpHdrLen,0,pcapTimeout,m_PcapErr)))
	throw PredException(m_PcapErr);
    ioctl(pcap_fileno(pcap),BIOCIMMEDIATE,&m_immedDev);
    
    char pfilter[hwAddrStrLen+32]; //pcap filter string
    bpf_program fp; //pcap filtering rules

    snprintf(pfilter,sizeof(pfilter),
       	"arp and ether dst %hX:%hX:%hX:%hX:%hX:%hX",
	     ifInfo.m_hwAddr[0],
	     ifInfo.m_hwAddr[1],
	     ifInfo.m_hwAddr[2],
	     ifInfo.m_hwAddr[3],
	     ifInfo.m_hwAddr[4],
	     ifInfo.m_hwAddr[5]);

    if(pcap_compile(pcap,&fp,pfilter,1,0x0)<0)
	return -1;
    
    if(pcap_setfilter(pcap,&fp)<0)
	return -1;
    
    u_int8_t *reply=NULL;
    packet request={NULL,0};
    pcap_pkthdr phdr;

    pthread_mutex_lock(&m_linkMutex);
	
    BuildEtherArp(ARPOP_REQUEST,
		  ifInfo.m_hwAddr,
		  &ifInfo.m_prAddr,
		  const_cast<u_int8_t*>(hwBroadcast),
		  &prAddr);
    
    if(libnet_adv_cull_packet(m_link,&request.m_packet,&request.m_packet_s)<0)
    {
	pthread_mutex_unlock(&m_linkMutex);
	return -1;
    }
    pthread_mutex_unlock(&m_linkMutex);
    for(size_t i=0;i<arpRetries;i++)
    {
	
	pthread_mutex_lock(&m_linkMutex);
	if(libnet_adv_write_link(m_link,request.m_packet,request.m_packet_s)<0)
	{
		libnet_adv_free_packet(m_link,request.m_packet);
	    pthread_mutex_unlock(&m_linkMutex);
	    return -1;
	}
	
	pthread_mutex_unlock(&m_linkMutex);
	
	//wait for 3 sec. then resend a request
	size_t j;
	for(j=0;!reply&&j<3;reply=const_cast<u_int8_t*>(pcap_next(pcap,&phdr)),j++);
	if(!reply&&j==3)
	    continue;
	else break;
    }
    pthread_mutex_lock(&m_linkMutex);
    libnet_adv_free_packet(m_link,request.m_packet);
    pthread_mutex_unlock(&m_linkMutex);

    pcap_close(pcap);
    if(!reply)
	return -1;
    ethernet_hdr *ethHdr;
    arp_hdr *arpHdr; 
    reinterpret_cast<u_int8_t*>(ethHdr)=reply;
    reinterpret_cast<u_int8_t*>(arpHdr)=reply+ethHdrLen;
    
    memcpy(hwAddr,reinterpret_cast<u_int8_t*>(arpHdr)+0x8,hwAddrLen);
    return 0;
}


inline void session::BuildEtherArp(u_int16_t arpOp,u_int8_t *shwAddr,in_addr_t *sprAddr,u_int8_t *dhwAddr,in_addr_t *dprAddr) throw(PredException)
{
    __session_namespace::BuildEtherArp(arpOp,shwAddr,sprAddr,dhwAddr,dprAddr,m_link);
}

int session::DumpConnection(u_int32_t index,
			    const char *filter,
			    const char *file,
			    size_t snaplen) const throw(PredException)
{
    return m_Connections[index]->Dump(filter,file,snaplen);
}
