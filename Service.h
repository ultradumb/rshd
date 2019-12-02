
#ifndef _SERVICE_H
#define _SERVICE_H


#ifdef __cplusplus
extern "C" {
#endif

// Service routine prototypes
VOID CmdInstallService(char* user, char* password, char* args);
VOID CmdRemoveService();
VOID CmdDebugService(int argc, char **argv);

extern BOOL bDebug;

// rshd related routines
void parseCommandLine (int argc, char** argv);


//////////////////////////////////////////////////////////////////////////////
// name of the executable
#define SZAPPNAME            "rshd"
// internal name of the service
#define SZSERVICENAME        "rshd"
// displayed name of the service
#define SZSERVICEDISPLAYNAME "RSH Daemon"
// list of service dependencies - "dep1\0dep2\0\0"
#define SZDEPENDENCIES       ""
//////////////////////////////////////////////////////////////////////////////



//////////////////////////////////////////////////////////////////////////////
//// todo: ServiceStart()must be defined by in your code.
////       The service should use ReportStatusToSCMgr to indicate
////       progress.  This routine must also be used by StartService()
////       to report to the SCM when the service is running.
////
////       If a ServiceStop procedure is going to take longer than
////       3 seconds to execute, it should spawn a thread to
////       execute the stop code, and return.  Otherwise, the
////       ServiceControlManager will believe that the service has
////       stopped responding
////
VOID ServiceStart(DWORD dwArgc, LPTSTR *lpszArgv);
VOID ServiceStop();
//////////////////////////////////////////////////////////////////////////////



//////////////////////////////////////////////////////////////////////////////
//// The following are procedures which
//// may be useful to call within the above procedures,
//// but require no implementation by the user.
//// They are implemented in service.c

//
//  FUNCTION: ReportStatusToSCMgr()
//
//  PURPOSE: Sets the current status of the service and
//           reports it to the Service Control Manager
//
//  PARAMETERS:
//    dwCurrentState - the state of the service
//    dwWin32ExitCode - error code to report
//    dwWaitHint - worst case estimate to next checkpoint
//
//  RETURN VALUE:
//    TRUE  - success 
//    FALSE - failure
//
BOOL ReportStatusToSCMgr(DWORD dwCurrentState, DWORD dwWin32ExitCode, DWORD dwWaitHint);


//
//  FUNCTION: AddToMessageLog(LPTSTR lpszMsg)
//
//  PURPOSE: Allows any thread to log an error message
//
//  PARAMETERS:
//    lpszMsg - text for message
//
//  RETURN VALUE:
//    none
//
void AddErrorToMessageLog(const LPTSTR lpszMsg);
void AddInfoToMessageLog(const LPTSTR lpszMsg);
//////////////////////////////////////////////////////////////////////////////


#ifdef __cplusplus
}
#endif

#endif
