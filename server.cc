#include "server.h"

namespace __server_namespace{
    server::server():m_ClientThreads(DefCliNum)
{

}

server::server(const sockaddr_storage &SrvAddr)
{
    //memcpy(&m_SrvAddr,&SrvAddr,sizeof(SrvAddr));
    /*m_Protocol=SrvAddr.ss_family;
    if((m_ListeningSocket=socket(m_Protocol,SOCK_STREAM,0))<0)
    throw PredException(L"socket()",errno);*/
    pthread_attr_t attr;
    int errcode=0;
    errcode=pthread_attr_init(&attr);
    if(errcode)
	throw ServException(L"pthread_attr_init()",errcode);
    errcode=pthread_attr_setdetachstate(&attr,PTHREAD_CREATE_DETACHED);
    if(!errcode){
	errcode=pthread_create(&m_MainThread,&attr,LaunchServer,this);
	if(errcode)
	    throw ServException(L"pthread_create()",errcode);
    }
    pthread_attr_destroy(&attr);
    if(errcode)
	throw ServException(L"pthread_attr_setdetachstate()",errcode);

}
server::~server()
{

}




void* server::LaunchServer(void *arg)
{
    server *theServer=reinterpret_cast<server*>(arg);
    return NULL;
}


}//__server_namespace
