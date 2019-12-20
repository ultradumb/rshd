#define VISUALCPP
//#define BORLANDCPP

#define VERSION_MAJOR 1
#define VERSION_MINOR 9

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include "service.h"

// stuff from doexec.c goes here
#ifdef GAPING_SECURITY_HOLE
	BOOL doexec(char *pr00gie, SOCKET ClientSocket, SOCKET ClientSocketErr);
#endif /* GAPING_SECURITY_HOLE */

// Function prototype for rcp handler
void rcpCommand(SOCKET rshClient, SOCKET& rshClientErr, char* Cmd );

// the .rhosts file path, relative to the "windir" directory
#define RHOSTS "rhosts"

// the rshd shutdown command
#define RSH_SHUTDOWN "stoprsh"

struct sockaddr_in anaddr; // socket address structure 
u_short rshPort; // the rshd port; basically, the 'cmd' port from services
u_short rshProto; // the rshd protocol ("tcp")
SOCKET rshServer; // the rshd server socket for incoming connections 
int client=0; // number of clients so far (used for debugging purposes only)
int runFlag=1; // cleared when the rshd daemon is to be shutdown
int securityFlag=1; // set to loosen up the security when not all information is available on the client 
int noRHosts=0; // set in order to disable .rhosts checking 
int noStdout=0, noStderr=0; // redirection flags 
int debugFlag=0;
int winntFlag=0; // OS flag; set if we're running on NT.  The "OS" env. variable has to be set to "Windows_NT"
int shell4dosFlag=0; // 4DOS shell flag 

#ifdef EBCEEB
int inputCygnusFlag;
int inputUnixFlag;
#endif /* EBCEEB */

// socket options variables 
int on=1;
struct linger linger;
#define LINGER_TIME 10

// the trusted host list; loaded from the .rhosts file 
struct _rhosts
{
  char* hostname;
	char* username;
  struct _rhosts* next;
}* rhostsList=NULL;

// debug //////////////////////////////////////////////////////////////////////
//
// debugging function
//
void
        debug (const char* message)
{
        if(debugFlag) {
                fprintf(stderr, "[%d] %s\n", client, message);
                fflush (stderr);
        }
}

// winsockError ///////////////////////////////////////////////////////////////
//
// displays the current Winsock error in text format
//
void winsockError ()
{
    fprintf(stderr, "[%d] Winsock error: ", client);
    int nErrCode=WSAGetLastError();
    switch(nErrCode)
    {
        case WSAENETDOWN:
            fprintf(stderr, "The network subsystem has failed.\n");
            break;
        case WSAEINTR:
            fprintf(stderr, "A blocking call was cancelled.  This can be caused by\n1) a short response time, or\n2) User interrupts the process.\n");
            break;
        case WSAEINPROGRESS:
            fprintf(stderr, "A blocking call is in progress.\n");
            break;
        case WSAENOBUFS:
            fprintf(stderr, "No buffer space is available.\n");
            break;
        case WSAENOTSOCK:
            fprintf(stderr, "Invalid socket descriptor.\n");
            break;
        case WSAEADDRINUSE:
            fprintf(stderr, "The specified address is already in use.\n");
            break;
        case WSAEADDRNOTAVAIL:
            fprintf(stderr, "The specified address is not available\nfrom the local machine.\n");
            break;
        case WSAECONNREFUSED:
            fprintf(stderr, "The connection attempt was refused.\n");
            break;
        case WSAEINVAL:
            fprintf(stderr, "The socket is not already bound to an address.\n");
            break;
        case WSAEISCONN:
            fprintf(stderr, "The socket is already connected.\n");
            break;
        case WSAEMFILE:
            fprintf(stderr, "The maximum number of sockets has exceeded.\n");
            break;
        case WSAENETUNREACH:
            fprintf(stderr, "Network cannot be reached from this host at this time.\n");
            break;
        case WSAETIMEDOUT:
            fprintf(stderr, "Attempt to connect timed out without establishing a connection.\n");
            break;
        case WSAENOTCONN:
            fprintf(stderr, "The socket is not connected.\n");
            break;
        case WSAESHUTDOWN:
            fprintf(stderr, "The socket has been shut down.\n");
            break;
        case WSAECONNABORTED:
            fprintf(stderr, "The virtual circuit was aborted due to timeout or other failure.\n");
            break;
        case WSAECONNRESET:
            fprintf(stderr, "The virtual circuit was reset by the remote side.\n");
            break;
        case WSAEACCES:
            fprintf(stderr, "The requested address is a broadcast address.\n");
            break;
        case WSAENETRESET:
            fprintf(stderr, "The connection must be reset.\n");
            break;
        case WSAHOST_NOT_FOUND:
            fprintf(stderr, "Authoritative Answer Host is not found.\n");
            break;
        default:
            fprintf(stderr, "Error number = %d.\n", nErrCode);
            break;
    }
}

// error //////////////////////////////////////////////////////////////////////
//
// display an error message and possibly the last Winsock error
//
void
        error (const char* message, int ex=1)
{
    fprintf(stderr, "[%d] *** ERROR: %s\n", client, message);
    winsockError();
    if(ex)
    {
        WSACleanup();
        exit(1);
    }
}

// mutex routines
HANDLE mutex=NULL;

void
    rshlock ()
{
    if(!mutex)
        mutex=CreateMutex(NULL, TRUE, NULL);
    else
        WaitForSingleObject(mutex, INFINITE);
}

void
    rshunlock ()
{
    ReleaseMutex(mutex);
}


// rresvport //////////////////////////////////////////////////////////////////
//
// the windows hack of rresvport; due to the time-out problem with the stderr port,
// rresvport will try to avoid assigning the same port twice for as long as possible
//

int
    rresvport (int* alport)
{
    struct sockaddr_in sin;
    int s;
    static int lastport=IPPORT_RESERVED; // static value of the last assigned port
    int i=IPPORT_RESERVED/2;

    // since lastport is a static variable, a locking mechanism is required...
    rshlock();

    *alport=lastport-1; // we take from where we left it last time

    sin.sin_family=AF_INET;
    sin.sin_addr.s_addr=INADDR_ANY;
    s=socket(AF_INET, SOCK_STREAM, 0);
    if(s<0)
    {
        rshunlock();
        return -1;
    }
    for(;i;i--,(*alport)--)
    {
        if(*alport==(IPPORT_RESERVED/2)) // BOZY 2019 move it at the beginning of the loop
            *alport=IPPORT_RESERVED;     // wrap up and start all over
        sin.sin_port=htons((u_short)*alport);
        if(bind(s, (struct sockaddr*)&sin, sizeof(sin))==0)
        {
            lastport=*alport;
            rshunlock();
            return s;
        }
        if(WSAGetLastError()!=WSAEADDRINUSE)
            break;
    }
    // ran out of available ports or weird error; shouldn't happen too often...
    closesocket(s);
    rshunlock();
    return -1;
}


// receive ////////////////////////////////////////////////////////////////////
//
// receive a string from the given socket
//
int
    receive (SOCKET rshClient, char* buff, int blen)
{
    int bufflen;
    int totallen=0;
    if (debugFlag) fprintf (stderr, "[%d] Receiving...", client);
    do
    {
        bufflen=recv(rshClient, buff+totallen, blen-totallen, 0);
        if(bufflen==SOCKET_ERROR)
            return bufflen;
        if(debugFlag)
            fprintf(stderr, " ...got %d chars.\n", bufflen);
        totallen+=bufflen;

    } while(bufflen && totallen<blen && buff[totallen-1]);
    if(!totallen)
        buff[0]=0;
    buff[totallen]=0;
    return totallen;
}

// dumpFile ///////////////////////////////////////////////////////////////////
//
// send back to the client whatever was redirected in a temporary file
//
void
    dumpFile (char* fileName, SOCKET s)
{
#define DUMP_BUFF_LEN 4096
    char buff[DUMP_BUFF_LEN];
    int bufflen;
    FILE* temp=fopen(fileName, "r");
    if(temp==NULL)
    {
        error("Cannot open temporary file...", 0);
        return;
    }
    while(!feof(temp))
    {
        buff[0]=0;
        fgets(buff, DUMP_BUFF_LEN, temp);
        bufflen=strlen(buff);
        if(bufflen)
            if(send(s, buff, bufflen, 0) < bufflen)
            {
                error("Error sending results.", 0);
                break;
            }
    }
    fclose(temp);
}

// runCommand /////////////////////////////////////////////////////////////////
//
// execute the command given in "comm" and send back the results;
// unless disabled thru command line options, both the stdout and
// the stderr of the command are redirected into temporary files
// which are then sent back to the client
//
void
    runCommand (SOCKET rshClient, SOCKET rshClientErr, char* comm)
{
    char buff[1024];
    char tempOut[128];
    char tempErr[128];
    char* tempDir=getenv("TEMP");

    if(!strcmp(comm, RSH_SHUTDOWN))
    {
        // the "rshShutdown" command is an internal one; it is used to
        // gracefully stop the rshd daemon

        strcpy(buff, "rshd shutdown!\n");
        int bufflen=strlen(buff);
        send(rshClient, buff, bufflen, 0);
        runFlag=0;
        closesocket(rshClient);
        if(rshClientErr!=INVALID_SOCKET)
            closesocket(rshClientErr);
        WSACleanup( );
        exit(0);
    }

#ifdef EBCEEB

    if( inputUnixFlag || inputCygnusFlag )
    {
#       include <ctype.h>

        char *p = comm;
        for( ; *p && isspace(*p) ; p++ );  // find name of program

        if( inputCygnusFlag && !strncmp( p, "//", 2 ) )
        {
            *p++ = *(p+2);                //  change "//d/" to "d:\"
            *p++ = ':';
            *p++ = '\\';
            strcpy( p, p+1 );
        }

        if( inputUnixFlag )
            for( ; *p && !isspace(*p) ; p++ )
                if( *p=='/' )
                    *p = '\\';
    }

#endif /* EBCEEB */

    if(shell4dosFlag)
        sprintf(buff, "(%s)", comm);
    else
        strcpy(buff, comm);
    if(!noStdout)
    {
        // stdout redirection on 
        *tempOut=0;
        if(tempDir)
        {
            strcpy(tempOut, tempDir);
#ifndef VISUALCPP
            strcat(tempOut, "\\");
#endif
        }
        tmpnam(tempOut+strlen(tempOut));
        strcat(buff, " >");
        strcat(buff, tempOut);
    }
    if(!noStderr && (winntFlag || shell4dosFlag))
    {
        // stderr redirection on 
        *tempErr=0;
        if(tempDir)
        {
            strcpy(tempErr, tempDir);
#ifndef VISUALCPP
            strcat(tempErr, "\\");
#endif
        }
        tmpnam(tempErr+strlen(tempErr));
        if(shell4dosFlag)
            strcat(buff, " >&>");
        else
            strcat(buff, " 2>");
        strcat(buff, tempErr);
    }
    if(debugFlag)
        fprintf(stderr, "[%d] Executing '%s'...\n", client, buff);
    // run the command and wait for it to end 
    system(buff);

    // send the results over...
    debug("Sending results...");
    // stdout goes to the main client port 
    if(!noStdout)
    {
        dumpFile(tempOut, rshClient);
        unlink(tempOut);
    }
    // if an additional port was specified, use it for stderr 
    if(!noStderr && (winntFlag || shell4dosFlag))
    {
        if(rshClientErr != INVALID_SOCKET)
            dumpFile(tempErr, rshClientErr);
        else
            // otherwise, send stderr to the same main client port 
            dumpFile(tempErr, rshClient);
        unlink(tempErr);
    }
}


// winsockCheck //////////////////////////////////////////////////////////////
//
// make sure we have the right winsock.dll version; 1.1 required 
//
void
    winsockCheck ()
{
    debug("Checking winsock.dll version...");
    WORD wVersionRequested;
    WSADATA wsaData;
    int err;
    wVersionRequested = MAKEWORD( 1, 1 );
    err = WSAStartup( wVersionRequested, &wsaData );
    if ( err != 0 )
        error("Unsupported version of winsock.dll!\n");

    // Confirm that the Windows Sockets DLL supports 1.1.
    // Note that if the DLL supports versions greater 
    // than 1.1 in addition to 1.1, it will still return 
    // 1.1 in wVersion since that is the version we 
    // requested.
    if ( LOBYTE( wsaData.wVersion ) != 1 || HIBYTE( wsaData.wVersion ) != 1
)
        error("Unsupported version of winsock.dll!\n");

    // The Windows Sockets DLL is acceptable. Proceed.
}


// initSocket /////////////////////////////////////////////////////////////////
//
// standard socket initialization procedure 
//
void
    initSocket ()
{
    // get port number for rshd 
    struct servent FAR* sp=getservbyname("cmd", "tcp");
    if(sp==NULL)
        error("Cannot determine port number for the rshd daemon.");
    rshPort=htons(sp->s_port);

    // get protocol number for tcp 
    LPPROTOENT lpProto=getprotobyname("tcp");
    if(!lpProto)
    {
        debug("Cannot obtain the protocol number; using default...");
        rshProto=IPPROTO_TCP;
    }
    else
        rshProto=lpProto->p_proto;

    debug("Creating socket...");
    // create socket 
    rshServer=socket(PF_INET, SOCK_STREAM, rshProto);
    if(rshServer==INVALID_SOCKET)
        error("Cannot allocate socket for the rshd daemon.");

    // bind our socket 
    anaddr.sin_port=htons(rshPort);
    anaddr.sin_addr.s_addr=INADDR_ANY;
    anaddr.sin_family=PF_INET;
    debug("Binding socket...");
    if(bind(rshServer, (struct sockaddr FAR*)&anaddr, sizeof(anaddr)))
    {
        closesocket(rshServer);
        error("Cannot bind to the rshd daemon port.");
    }
}


// openErrSocket //////////////////////////////////////////////////////////////
//
// if an additional port is received from the client, use it to create
// a socket for stderr output
//
int
    openErrSocket (SOCKET rshClient, SOCKET& rshClientErr, char* buff)
{
    // read the stderr port number 
    rshClientErr=INVALID_SOCKET;
    u_short errPort=(u_short)atoi(buff);
    if(!errPort)
    {
        error("Wrong stderr port number!", 0);
        rshClientErr = INVALID_SOCKET; // BOZY 2019 for doexec()
        return 1;
    }
//    if(debugFlag)
//        fprintf(stderr, "[%d] openErrSocket client stderr port: %d\n", client, errPort);

    // make sure the client stderr port is within the reserved range 
    if(errPort<512 || errPort>1023)
    {
        error("Client stderr port outside the 512-1023 range\n");
        return 0;
    }
    // get the necessary info on the stderr socket 
    struct sockaddr_in cliaddr;
    int len=sizeof(cliaddr);
    if(getpeername(rshClient, (struct sockaddr FAR*)&cliaddr, &len))
    {
        error("Cannot determine client's IP address!", 0);
        closesocket(rshClientErr);
        rshClientErr=INVALID_SOCKET;
        return 1;
    }

    // create the new socket 
    int lport=IPPORT_RESERVED-2;
    rshClientErr=rresvport(&lport);
    if(rshClientErr==INVALID_SOCKET)
    {
        error("Cannot create stderr socket!", 0);
        return 1;
    }

    if(debugFlag)
        fprintf(stderr, "[%d] openErrSocket local stderr port: %d <<<---\n", client, lport);
    if(setsockopt(rshClientErr, SOL_SOCKET, SO_KEEPALIVE, (char*)&on, sizeof(on))<0)
        error("Cannot set SO_KEEPALIVE!", 0);
    linger.l_onoff=0;
    linger.l_linger=LINGER_TIME;
    if(setsockopt(rshClientErr, SOL_SOCKET, SO_LINGER, (char*)&linger, sizeof(linger))<0)
        error("Cannot set SO_LINGER!", 0);

    // now, connect to the client stderr port 
    cliaddr.sin_family=PF_INET;
    cliaddr.sin_port=htons(errPort);
    if(connect(rshClientErr, (struct sockaddr FAR*)&cliaddr, sizeof(cliaddr)))
    {
        if (debugFlag) { fprintf (stderr, "--->>> client stderr port %d <<<---\n", client, errPort); }
        error("Cannot connect to the client stderr port!", 0);
        closesocket(rshClientErr);
        rshClientErr=INVALID_SOCKET;
    }
    return 1;
}


// hostAndUserCheck //////////////////////////////////////////////////////////////
//
// performs a security check on the remote hostname, username;
// normally, the host and user should be listed in the .rhosts file
//
// taken from https://github.com/VladislavShcherba/RSHD/blob/master/rshd.cpp
int
    hostAndUserCheck (char* hostname, char* username)
{
    if (debugFlag)
    	fprintf(stderr, "[%d] Checking host '%s' and user '%s' against the .rhosts file...\n", client, hostname, username);
    struct _rhosts* ptr=rhostsList;
    while(ptr)
    {
        if(!strcmpi(ptr->hostname, hostname) && !strcmpi(ptr->username, username) || !strcmpi(ptr->hostname, "+"))
            return 1;
        ptr=ptr->next;
    }
    fprintf(stderr, "[%d] Access denied to host %s - %s...\n", client, hostname, username);
    return 0;
}


// clientCheck ////////////////////////////////////////////////////////////////
//
// performs a security clearance on the remote client;
// the following things should check:
// - the foreign port should be in the 512-1023 range;
// - the remote host should be listed in the .rhosts file;
// - the remote client should be allowed to login from the remote host
// the 'securityFlag' is used to resolve the cases when not enough
// information is available (the default is to let people pass)
//
int
    clientCheck (SOCKET rshClient, char *username)
{
    // get the necessary info on the client socket 
    struct sockaddr_in cliaddr;
    int len=sizeof(cliaddr);
    if(getpeername(rshClient, (struct sockaddr FAR*)&cliaddr, &len))
    {
        error("Cannot determine client's IP address!", 0);
        return securityFlag;
    }
    // make sure the client port is within the reserved  range 
    cliaddr.sin_port=ntohs(cliaddr.sin_port);
    if(debugFlag)
        fprintf(stderr, "[%d] Client port: %d...\n", client, cliaddr.sin_port);
    if(cliaddr.sin_port<512 || cliaddr.sin_port>1023)
    {
        fprintf(stderr, "[%d] Client port outside the 512-1023 range!\n",
            client);
        return 0;
    }

    // now, check the remote host 
    if(noRHosts)
        return 1; // .rhosts checking disabled 
    struct hostent* remoteHostPtr=gethostbyaddr((const char FAR*)&cliaddr.sin_addr,
        4, PF_INET);
    if(!remoteHostPtr)
    {
        fprintf(stderr, "[%d] Cannot determine remote host credentials!\n", client);
        return securityFlag;
    }
//    if(debugFlag)
//        fprintf(stderr, "[%d] Client host: %s...\n", client,
//            remoteHostPtr->h_name);
    return hostAndUserCheck(remoteHostPtr->h_name, username);
}

//
// map command to accommodate for existing scripts calling perl programs from rsh in AIX
// this can be used as a simple tool to prevent running dangerous commands like cmd.exe
//
void mapcommand (const char *mcmd, char *rescmd)
{
	static char c[4096];
	char xlfrom[][128] = {"bin/getuniv.pl",              "bin/getuniv-sap.pl",          "perl",          											 "echo"};
	char xlto[][128]   = {"c:\\getunivsvc\\getuniv.bat", "c:\\getunivsvc\\getuniv.bat", "c:\\Strawberry\\perl\\bin\\perl.exe", "c:\\Strawberry\\perl\\bin\\perl.exe c:\\getunivsvc\\echo.pl"};
	
	strcpy (c, mcmd); // leave unchanged if no mapping occured
	
	for (int i = 0; i < sizeof(xlfrom) / sizeof(xlfrom[0]); i++) {
		if (!_strnicmp (mcmd, xlfrom[i], strlen(xlfrom[i]))) { // compare ignoring case
			strcpy (c, xlto[i]);
			if (strchr (mcmd, ' ') != NULL) { // found additional arguments to command? copy them over
				strcat (c, strchr (mcmd, ' '));
			}
		}
	}
	strcpy (rescmd, c);
	return;
}

// command ////////////////////////////////////////////////////////////////////
//
// process the input from the client and runs the received command 
//
void
    command (SOCKET rshClient, SOCKET &rshClientErr)
{
    char buff[4096];
    char rescmd[4096];
    int blen=sizeof(buff)-1;

    // receive data from the client 
    if(receive(rshClient, buff, blen)==SOCKET_ERROR)
    {
        error("Cannot receive stderr port", 0);
        return;
    }

    int crt=0;
    if(buff[crt])
    {
        // an additional socket will be open for stderr 
        if(debugFlag)
            fprintf(stderr, "[%d] stderr port: %s\n", client, buff);
        if(!openErrSocket(rshClient, rshClientErr, buff))
            return;
    }

    // skip the stderr port 
    while(buff[crt++]);
    // retrieve and then skip the remote user name 
    if(!buff[crt])
    {
        // the remote user name hasn't been provided yet 
        if(receive(rshClient, buff, blen)==SOCKET_ERROR)
        {
            error("Cannot receive remote user name", 0);
            return;
        }
        crt=0;
    }
    if(debugFlag)
        fprintf(stderr, "[%d] Remote user name: %s, ", client, buff+crt);
		char username[1024]; // taken from https://github.com/VladislavShcherba/RSHD/blob/master/rshd.cpp
		strcpy(username, buff+crt);
    while(buff[crt++]);
    // ignore the local user name 
    if(!buff[crt])
    {
        // the local user name hasn't been provided yet 
        if(receive(rshClient, buff, blen)==SOCKET_ERROR)
        {
            error("Cannot receive local user name", 0);
            return;
        }
        crt=0;
    }
    if(debugFlag)
        fprintf(stderr, "local user name: %s\n", buff+crt);
    while(buff[crt++]);
    // the rest is the command to be executed 
    if(!buff[crt])
    {
        // the command hasn't been provided yet 
        if(receive(rshClient, buff, blen)==SOCKET_ERROR)
        {
            error("Cannot receive remote command.", 0);
            return;
        }
        crt=0;
    }
    if(debugFlag)
        fprintf(stderr, "[%d] Command: '%s'\n", client, buff+crt);

    // Check to see if the connected system is in the .rhosts file.
    //debug("Checking client...");
    if(!clientCheck(rshClient, username))
    {
                char buff[50];
                // Error condition:  Permission denied for remote system access
                buff[0]=1;
                sprintf( &buff[1], "Permission Denied\n");
                if(send(rshClient, buff, strlen( &buff[1])+1 , 0) < 1)
                {
                        error("Error sending result status", 0);
                }
                Sleep( 1000 );
        return;
    }

    //debug("Sending null byte result...");
    buff[0]=0;
    if(send(rshClient, buff, 1, 0) < 1)
    {
        error("Error sending result status", 0);
        return;
    }

    if(!strcmp(buff+crt, RSH_SHUTDOWN))
    {
        // the "stoprsh" command is an internal one; it is used to
        // gracefully stop the rshd daemon
        char clntmsg[256];
        strcpy(clntmsg, "rshd shutdown!\n");
        int bufflen=strlen(clntmsg);
        send(rshClient, clntmsg, bufflen, 0);
        runFlag=0;
        closesocket(rshClient);
        if(rshClientErr!=INVALID_SOCKET)
            closesocket(rshClientErr);
        WSACleanup( );
        exit(0);
    }
    // Check to see if this is a command or an rcp request
    if ( strncmp( buff+crt, "rcp -", 5 ) ) {
       	// run the command and send the results over
       	// runCommand(rshClient, rshClientErr, buff+crt); - not needed, see doexec.cpp
       	mapcommand ((const char *)buff+crt, (char *)rescmd); // map the command according to table
       	if(debugFlag) fprintf(stderr, "[%d] Mapped command: '%s'\n", client, rescmd);
       	doexec (rescmd, rshClient, rshClientErr);
    }  else // Process the rcp request
       	rcpCommand( rshClient, rshClientErr, buff+crt );
}


// clientThread ///////////////////////////////////////////////////////////////
//
// this is the client thread; it is started for each new connection 
//
long
    clientThread (SOCKET* rshClientPtr)
{
    debug("Thread started...");
    SOCKET rshClient=*rshClientPtr;
    SOCKET rshClientErr=INVALID_SOCKET;
    delete rshClientPtr;
    debug("Setting options on the main socket...");
    if(setsockopt(rshClient, SOL_SOCKET, SO_KEEPALIVE, (char*)&on, sizeof(on))<0)
        error("Cannot set SO_KEEPALIVE!\n", 0);
    linger.l_onoff=1;
    linger.l_linger=LINGER_TIME;
    if(setsockopt(rshClient, SOL_SOCKET, SO_LINGER, (char*)&linger, sizeof(linger))<0)
        error("Cannot set SO_LINGER!\n", 0);

    debug("Processing client data...");
    command(rshClient, rshClientErr);
    debug("Closing main socket...");

    linger.l_onoff=1;
    linger.l_linger=0;
    // trying BSD/Linux trick - set linger time to 0 to close connection with RST
    if(setsockopt(rshClient, SOL_SOCKET, SO_LINGER, (char*)&linger, sizeof(linger))<0)
     		fprintf(stderr, "[%d] Cannot reset rshClient SO_LINGER to 0!\n", client);
    shutdown(rshClient, SD_RECEIVE); // 2
    closesocket(rshClient);
    if(rshClientErr!=INVALID_SOCKET)
    {
        debug("Closing stderr socket...");
        linger.l_onoff=1;
    		linger.l_linger=0;
    		// trying BSD/Linux trick - set linger time to 0 to close connection with RST
    		if(setsockopt(rshClientErr, SOL_SOCKET, SO_LINGER, (char*)&linger, sizeof(linger))<0)
        		fprintf(stderr, "[%d] Cannot reset rshClientErr SO_LINGER to 0!\n", client);
        shutdown(rshClientErr, SD_RECEIVE); // BOZY 2019 changed from SD_BOTH(2) to avoid TIME_WAIT port state
        closesocket(rshClientErr);
    }
    debug("Client disconnected...");
    return 0;
}


// myBlockingHook /////////////////////////////////////////////////////////////
//
// Win32 hook called within all blocking socket routines; used to cancel the
// blocking call if the shutdown flag was set
//
BOOL
    myBlockingHook ()
{
    MSG msg;
    BOOL ret;

    // cancel current call if shutdown flag is set
    if(!runFlag)
            WSACancelBlockingCall();

    ret = (BOOL) PeekMessage(&msg, NULL, 0, 0, PM_REMOVE);
    if (ret)
    {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return ret;
}


// loop ///////////////////////////////////////////////////////////////////////
//
// loop for new connections 
//
void
    loop ()
{
    DWORD threadID;

    // set my own blocking call hook
    WSASetBlockingHook((FARPROC)&myBlockingHook);

    debug("Listening...");
    // listen for connections
    if(listen(rshServer, 5))
    {
        closesocket(rshServer);
        error("Error while listening to the rshd daemon port.");
    }

    debug("Ready for connections...");
    while(1)
    {
        debug("Accepting connection...");
        // ready to accept connections
        int len=sizeof(anaddr);
        SOCKET rshClient=accept(rshServer, (struct sockaddr FAR*)&anaddr, &len);
        if(!runFlag)
            return;
        if(rshClient==INVALID_SOCKET)
        {
            error("Error accepting connection from rsh client.", 0);
            continue;
        }
        client++;
        debug("Client connected!");
        // got a new connection; start a separate thread 
        SOCKET* rshSocket=new SOCKET;
        if(!rshSocket)
        {
            error("Heap overflow!", 0);
            continue;
        }
        *rshSocket=rshClient;
        debug("Starting client thread...");
        HANDLE threadHnd=CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)clientThread,
            (LPVOID)rshSocket, 0, (LPDWORD)&threadID);
        if(!threadHnd)
            error("Cannot start client thread...");
        else
            CloseHandle(threadHnd);
    }
}


// parseCommandLine ///////////////////////////////////////////////////////////
//
// check for command line parameters and set various flags 
//
void
    parseCommandLine (int argc, char** argv)
{
    for(int i=1; i<argc; i++)
        if(!strcmpi(argv[i], "-install"))
        {
			char* inst_args = (char*)calloc(sizeof(argv), sizeof(char));
			strcat(inst_args," ");
			char* user = NULL;
			char* password = NULL;

			for(int x=i+1; x<argc; x++) {
				if(!strcmpi(argv[x], "-u")) {
					user = argv[x+1];
					x++;
				} else if(!strcmpi(argv[x], "-p")) {
					password = argv[x+1];
					x++;
				} else {
					strcat(inst_args,argv[x]);
					strcat(inst_args," ");
				}
			}

			printf("Installing service as user: %s pw: %s args: %s\n", user, password, inst_args);
            CmdInstallService(user, password, inst_args);
            exit(0);
        }
        else
        if(!strcmpi(argv[i], "-remove"))
        {
            CmdRemoveService();
            exit(0);
        }
        else
        if(!strcmpi(argv[i], "-d"))
        {
            debugFlag=1;
            bDebug = TRUE;
            //comment by EBCEEB: CmdDebugService(argc, argv);
        }
        else
        if(!strcmpi(argv[i], "-s"))
        {
                securityFlag=0;
                debug("Tight security enabled!");
        }
        else
        if(!strcmp(argv[i], "-1"))
        {
                noStdout=1;
                debug("No stdout redirection!");
        }
        else
        if(!strcmp(argv[i], "-2"))
        {
                noStderr=1;
                debug("No stderr redirection!");
        }
        else
        if(!strcmp(argv[i], "-4"))
        {
                shell4dosFlag=1;
                debug("Running in 4DOS!");
        }
        else
        if(!strcmpi(argv[i], "-r"))
        {
                noRHosts=1;
                debug(".rhosts checking disabled!");
        }
        else
        if(!strcmpi(argv[i], "-v"))
        {
            fprintf(stderr, "\nrshd - remote shell daemon for Windows /95/NT/2k, version %d.%d\n%s",
                    VERSION_MAJOR, VERSION_MINOR, "Check http://rshd.sourceforge.net/ for updates\n");
            exit(0);
        }
#ifdef EBCEEB
        else
        if(!strcmpi(argv[i], "-cygnus"))
        {
            inputUnixFlag = 1;
            inputCygnusFlag = 1;
            debug("Allow Cygnus-like drive and program name");
        }
        else
        if(!strcmpi(argv[i], "-unix"))
        {
            inputUnixFlag = 1;
            debug("Allow Unix-like program name with '/' instead of '\\'");
        }
#endif /* EBCEEB */
        else
        if(!strcmp(argv[i], "-h")
#ifdef EBCEEB
        || !strcmp(argv[i], "--help")
        || !strcmp(argv[i], "-?")
        || !strcmp(argv[i], "/?")
#endif
        )
        {
// this is just to be friendly
            fprintf(stderr,  "\nrshd - remote shell daemon for Windows 95/NT,version %d.%d\n\n\
Usage:\n\trshd [ -dhrvs124 ]\n\nCommand line options:\n\
\t-install\tinstall the service\n\
\t-u <user name>\tIn the form DomainName\\UserName (.\\UserName for local)\n\
\t-p <user password>\t\n\
\t-remove\tremove the service\n\
\t-d\tdebug output\n\
\t-r\tno .rhosts checking\n\
\t-s\ttighter security\n\
\t-4\t4DOS or 4NT command shell\n\
\t-1\tno stdout redirection\n\
\t-2\tno stderr redirection\n\
\t-v\tdisplay rshd version\n\
\t-h\tthis help screen\n", VERSION_MAJOR, VERSION_MINOR);

#ifdef EBCEEB
            fprintf(stderr, "\n"
            "\t-cygnus\tallow Cygnus-like drive name in program name: //d/\n"
            "\t-unix\tallow Unix-like program name\n" );
#endif
            exit(0);
        }
        else
            fprintf(stderr, "Ignoring unknown option '%s'...\n", argv[i]);

    // since we're here, check some environment variables
    char* os=getenv("OS");
    if(os && !strcmp(os, "Windows_NT"))
        winntFlag=1;
    else
        winntFlag=0; // "OS" undefined; most probably Windows 95

    // placed here by EBCEEB
    if( bDebug )
    {
        CmdDebugService(argc, argv);
        exit(0);
    }
}


// loadRHosts /////////////////////////////////////////////////////////////////
//
// create a list of trusted hosts from the .rhosts file
//
void
    loadRHosts ()
{
    rhostsList=NULL;
    char* windir=getenv("windir");
    if(!windir)
        error("The WINDIR environment variable is not set!");
    char rhosts[256];
    strcpy(rhosts, windir);
    strcat(rhosts, "\\");
    strcat(rhosts, RHOSTS);
    if(debugFlag)
        fprintf(stderr, "[%d] Loading %s...\n", client, rhosts);
    FILE* rhostsFile=fopen(rhosts, "r");
    if(!rhostsFile)
        error("Cannot open the .rhosts file.  Either create one or use the '-r' option...");
    char buff[1024];
    buff[1023]=0;
    while(!feof(rhostsFile))
    {
        fgets(buff, 1023, rhostsFile);
        if(feof(rhostsFile))
            break;
        int i=0;
        if(buff[i]=='#')
            continue; // ignoring comment line 
        while(buff[i] && buff[i]!=' ' && buff[i]!='\t' && buff[i]!='\n')
            i++;
        if(!i)
            continue; // empty line 
        char* hostname=(char*)calloc(sizeof(char), i+1);
        strncpy(hostname, buff, i);
        struct _rhosts* rhostCell=new struct _rhosts;
        if(!rhostCell)
            error("Heap overflow!");
        rhostCell->next=rhostsList;
        rhostCell->hostname=hostname;
        rhostsList=rhostCell;
        if(debugFlag)
            fprintf(stderr, "[%d] Trusting host %s...\n", client, hostname);
    }
    fclose(rhostsFile);
}


// main ///////////////////////////////////////////////////////////////////////
// this event is signalled when the
// service should end
//
HANDLE  hServerStopEvent = NULL;


//
//  FUNCTION: ServiceStart
//
//  PURPOSE: Actual code of the service
//           that does the work.
//
//  PARAMETERS:
//    dwArgc   - number of command line arguments
//    lpszArgv - array of command line arguments
//
//  RETURN VALUE:
//    none
//
//
VOID ServiceStart (DWORD dwArgc, LPTSTR *lpszArgv)
{
    HANDLE                  hEvents[2] = {NULL, NULL};

    ///////////////////////////////////////////////////
    //
    // Service initialization
    //

    // report the status to the service control manager.
    //
    if (!ReportStatusToSCMgr(
        SERVICE_START_PENDING, // service state
        NO_ERROR,              // exit code
        3000))                 // wait hint
                return;

    // create the event object. The control handler function signals
    // this event when it receives the "stop" control code.
    //
    hServerStopEvent = CreateEvent(
        NULL,    // no security attributes
        TRUE,    // manual reset event
        FALSE,   // not-signalled
        NULL);   // no name

    if ( hServerStopEvent == NULL)
                return;

    hEvents[0] = hServerStopEvent;

    // report the status to the service control manager.
    //
    if (!ReportStatusToSCMgr(
        SERVICE_START_PENDING, // service state
        NO_ERROR,              // exit code
        3000))                 // wait hint
                return;

    // create the event object object use in overlapped i/o
    //
    hEvents[1] = CreateEvent(
        NULL,    // no security attributes
        TRUE,    // manual reset event
        FALSE,   // not-signalled
        NULL);   // no name

    if ( hEvents[1] == NULL)
                return;

    // report the status to the service control manager.
    //
    if (!ReportStatusToSCMgr(
        SERVICE_START_PENDING, // service state
        NO_ERROR,              // exit code
        3000))                 // wait hint
                return;

        // now, do the real work
    winsockCheck();
    if(!noRHosts)
        loadRHosts();

    // report the status to the service control manager.
    //
    if (!ReportStatusToSCMgr(
        SERVICE_START_PENDING, // service state
        NO_ERROR,              // exit code
        3000))                 // wait hint
                return;

    initSocket();

    // report the status to the service control manager.
    //
    if (!ReportStatusToSCMgr(
        SERVICE_RUNNING,       // service state
        NO_ERROR,              // exit code
        0))                    // wait hint
                return;

    //
    // End of initialization
    //
    ////////////////////////////////////////////////////////

    ////////////////////////////////////////////////////////
    //
    // Service is now running, perform work until shutdown
    //

    AddInfoToMessageLog((LPTSTR)"RSH Daemon service started.");

    loop();

    if (hServerStopEvent)
        CloseHandle(hServerStopEvent);

    if (hEvents[1]) // overlapped i/o event
        CloseHandle(hEvents[1]);
    WSACleanup();
        AddInfoToMessageLog((LPTSTR)"RSH Daemon service stopped.");
}


//
//  FUNCTION: ServiceStop
//
//  PURPOSE: Stops the service
//
//  PARAMETERS:
//    none
//
//  RETURN VALUE:
//    none
//
//  COMMENTS:
//    If a ServiceStop procedure is going to
//    take longer than 3 seconds to execute,
//    it should spawn a thread to execute the
//    stop code, and return.  Otherwise, the
//    ServiceControlManager will believe that
//    the service has stopped responding.
//
VOID ServiceStop()
{
        runFlag=0;
    if ( hServerStopEvent )
        SetEvent(hServerStopEvent);
}