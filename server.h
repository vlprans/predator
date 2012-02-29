#ifndef __SERVER_H
#define __SERVER_H

#include "predator.h"
#include <vector>
//server is designed in protocol-independent way, 
//so that both IPv4 and IPv6 (UNIX domain protocol may be
//added also) are supported
namespace __server_namespace{ 
using namespace std;
class server
{
public:
    server();
    server(const sockaddr_storage &SrvAddr);
    ~server();
private:
    int m_ListeningSocket;
    pthread_t m_MainThread;//that's where listening happens
    vector<pthread_t> m_ClientThreads;
    //sockaddr_storage m_SrvAddr;//universal address storage
    sa_family_t m_Protocol;
private:
    static void* LaunchServer(void *arg);

private://consts
    static const u_int16_t Port=3902;//random one
    static const u_int32_t DefCliNum=1;//we allow several clients, but only one is generally online  
    

    class ServException:protected PredException
    {
    public:
	explicit ServException(std::wstring func,int code,int IsCritical=0){}
	explicit ServException(std::wstring func,std::wstring descr,int IsCritical=0){}
	const wchar_t* what() const throw(){
	    return (L"Server: "+ m_msg).c_str();
	 }
    };
};

}//__server_namespace


#endif //__SERVER_H
