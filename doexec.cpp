// for license see license.txt

// Modified 12/27/2004 by Chris Wysopal <weld@vulnwatch.com>
// fixed vulnerability found by hat-squad

// portions Copyright (C) 1994 Nathaniel W. Mishkin
// code taken from rlogind.exe

#include <stdlib.h>
#include <stdio.h>
#include <winsock2.h>
#include <winbase.h>
#include <string>

#ifdef GAPING_SECURITY_HOLE

#ifdef __cplusplus
#define ExitThread(n) return
#endif


#define BUFFER_SIZE 200

//
// Structure used to describe each session
//
typedef struct {

    //
    // These fields are filled in at session creation time
    //
    HANDLE  ReadPipeHandle;         // Handle to shell stdout pipe
    HANDLE	ReadErrPipeHandle;			// stderr pipe
    HANDLE  WritePipeHandle;        // Handle to shell stdin pipe
    HANDLE  ProcessHandle;          // Handle to shell process

    //
    //
    // These fields are filled in at session connect time and are only
    // valid when the session is connected
    //
    SOCKET  ClientSocket;
    SOCKET	ClientSocketErr;
    HANDLE  ReadShellThreadHandle;  // Handle to session shell-read thread
    HANDLE	ReadShellErrThreadHandle;	// Handle too session shell-stderr thread
    HANDLE  WriteShellThreadHandle; // Handle to session shell-write thread

} SESSION_DATA, *PSESSION_DATA;


//
// Private prototypes
//

static HANDLE
StartShell(
		char *pr00gie,
    HANDLE StdinPipeHandle,
    HANDLE StdoutPipeHandle,
    HANDLE StderrPipeHandle
    );

static VOID
SessionReadShellThreadFn(
    PSESSION_DATA Parameter
    );

static VOID // BOZY 2019 - new function for STDERR
SessionReadShellErrThreadFn(
    PSESSION_DATA Parameter
    );

static VOID
SessionWriteShellThreadFn(
    PSESSION_DATA Parameter
    );

extern int debugFlag;
extern void debug (const char *); // from rshd.cpp
extern void winsockError();

/* holler :
   changed to real varargs  */

static void holler (const char *str, ...) {
	va_list argp;
	if (debugFlag) {
		va_start(argp, str);
			vfprintf(stderr, str, argp);
		va_end(argp);
		if (WSAGetLastError()) winsockError();
			else fprintf(stderr, "\n");
	}
}

std::string GetLastErrorAsString()
{
    //Get the error message, if any.
    DWORD errorMessageID = ::GetLastError();
    if(errorMessageID == 0)
        return std::string(); //No error message has been recorded

    LPSTR messageBuffer = nullptr;
    size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                                 NULL, errorMessageID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);

    std::string message(messageBuffer, size-2); // skip newline/cr
    message = std::to_string(errorMessageID) + ": " + message;

    //Free the buffer.
    LocalFree(messageBuffer);

    return message;
}

// **********************************************************************
//
// CreateSession
//
// Creates a new session. Involves creating the shell process and establishing
// pipes for communication with it.
//
// Returns a handle to the session or NULL on failure.
//

static PSESSION_DATA
CreateSession(
    char *pr00gie,
    SOCKET ClientSocketErr
    )
{
    PSESSION_DATA Session = NULL;
    BOOL Result;
    SECURITY_ATTRIBUTES SecurityAttributes;
    HANDLE ShellStdinPipe = NULL;
    HANDLE ShellStdoutPipe = NULL;
    HANDLE ShellStderrPipe = NULL; // BOZY 2019

    //
    // Allocate space for the session data
    //
    Session = (PSESSION_DATA) malloc(sizeof(SESSION_DATA));
    if (Session == NULL) {
        return(NULL);
    }

    //
    // Reset fields in preparation for failure
    //
    Session->ReadPipeHandle  = NULL;
    Session->ReadErrPipeHandle = NULL; // BOZY 2019
    Session->WritePipeHandle = NULL;


    //
    // Create the I/O pipes for the shell
    //
    SecurityAttributes.nLength = sizeof(SecurityAttributes);
    SecurityAttributes.lpSecurityDescriptor = NULL; // Use default ACL
    SecurityAttributes.bInheritHandle = TRUE; // Shell will inherit handles

    Result = CreatePipe(&Session->ReadPipeHandle, &ShellStdoutPipe,
                          &SecurityAttributes, 0);
    if (!Result) {
        holler("CreateSession: failed to create shell stdout pipe, error = %s",
					(const char *)GetLastErrorAsString().c_str());
        goto Failure;
    }
    Result = CreatePipe(&ShellStdinPipe, &Session->WritePipeHandle,
                        &SecurityAttributes, 0);
    if (!Result) {
        holler("CreateSession: failed to create shell stdin pipe, error = %s",
					(const char *)GetLastErrorAsString().c_str());
        goto Failure;
    }
		//----------------------
		if(ClientSocketErr != INVALID_SOCKET) { // BOZY 2019 - we got separate STDERR socket
			    Result = CreatePipe(&Session->ReadErrPipeHandle, &ShellStderrPipe,
                        &SecurityAttributes, 0);
    	if (!Result) {
      	  holler("CreateSession: failed to create shell stderr pipe, error = %s",
							(const char *)GetLastErrorAsString().c_str());
        	goto Failure;
    	}
		}
		//----------------------

    //
    // Start the shell
    //
    Session->ProcessHandle = StartShell(pr00gie, ShellStdinPipe, ShellStdoutPipe, ShellStderrPipe);

    //
    // We're finished with our copy of the shell pipe handles
    // Closing the runtime handles will close the pipe handles for us.
    //
    CloseHandle(ShellStdinPipe);
    CloseHandle(ShellStdoutPipe);
    if (ShellStderrPipe) // BOZY 2019 - close STDERR pipe, if exists
    	CloseHandle(ShellStderrPipe);

    //
    // Check result of shell start
    //
    if (Session->ProcessHandle == NULL) {
        //holler("Failed to execute '%s'", pr00gie);
			
        goto Failure;
    }

    //
    // The session is not connected, initialize variables to indicate that
    //
    Session->ClientSocket = INVALID_SOCKET;
		Session->ClientSocketErr = INVALID_SOCKET; // BOZY 2019
    //
    // Success, return the session pointer as a handle
    //
    return(Session);

Failure:

    //
    // We get here for any failure case.
    // Free up any resources and exit
    //
		//if (debugFlag) { fprintf(stderr,"[doexec] CreateSession reached Failure label\n"); }
    if (ShellStdinPipe != NULL)
        CloseHandle(ShellStdinPipe);
    if (ShellStdoutPipe != NULL)
        CloseHandle(ShellStdoutPipe);
    if (ShellStderrPipe != NULL) // BOZY 2019
        CloseHandle(ShellStderrPipe);

    if (Session->ReadPipeHandle != NULL)
        CloseHandle(Session->ReadPipeHandle);
    if (Session->ReadErrPipeHandle != NULL) // BOZY 2019
        CloseHandle(Session->ReadErrPipeHandle);
    if (Session->WritePipeHandle != NULL)
        CloseHandle(Session->WritePipeHandle);

    free(Session);

    return(NULL);
}


BOOL
doexec(
		char *pr00gie,
    SOCKET  ClientSocket,
    SOCKET	ClientSocketErr
    )
{
    PSESSION_DATA   Session = CreateSession(pr00gie, ClientSocketErr);
    SECURITY_ATTRIBUTES SecurityAttributes;
    DWORD ThreadId;
    HANDLE HandleArray[4]; // BOZY 2019 - added 4th element - STDERR
		int i;
	
		if (Session == NULL) { return FALSE; } // failed to start command

    SecurityAttributes.nLength = sizeof(SecurityAttributes);
    SecurityAttributes.lpSecurityDescriptor = NULL; // Use default ACL
    SecurityAttributes.bInheritHandle = FALSE; // No inheritance

    //
    // Store the client socket handle in the session structure so the thread
    // can get at it. This also signals that the session is connected.
    //
    Session->ClientSocket = ClientSocket;
		Session->ClientSocketErr = ClientSocketErr;
    //
    // Create the session threads
    //
    Session->ReadShellThreadHandle = CreateThread(&SecurityAttributes, 0,
                     (LPTHREAD_START_ROUTINE) SessionReadShellThreadFn,
                     Session, 0, &ThreadId);

    if (Session->ReadShellThreadHandle == NULL) {
        holler("doexec: failed to create ReadShell session thread, error = %s",
					(const char *)GetLastErrorAsString().c_str());

        //
        // Reset the client pipe handle to indicate this session is disconnected
        //
        Session->ClientSocket = INVALID_SOCKET;

        return(FALSE);
    }
		// -------------------------------------------------------------------------
		if (ClientSocketErr != INVALID_SOCKET) { // BOZY 2019 - add thread for STDERR
			    Session->ReadShellErrThreadHandle = CreateThread(&SecurityAttributes, 0,
          	           (LPTHREAD_START_ROUTINE) SessionReadShellErrThreadFn,
            	         Session, 0, &ThreadId);

    			if (Session->ReadShellErrThreadHandle == NULL) {
        			holler("doexec: failed to create ReadShellErr session thread, error = %s",
								(const char *)GetLastErrorAsString().c_str());

        			//
        			// Reset the client pipe handle to indicate this session is disconnected
        			//
        			Session->ClientSocketErr = INVALID_SOCKET;
        			TerminateThread(Session->ReadShellThreadHandle, 0);
        			
      	  		return(FALSE);
    			}
		} else Session->ReadShellErrThreadHandle = NULL;
		// -------------------------------------------------------------------------

    Session->WriteShellThreadHandle = CreateThread(&SecurityAttributes, 0,
                     (LPTHREAD_START_ROUTINE) SessionWriteShellThreadFn,
                     Session, 0, &ThreadId);

    if (Session->WriteShellThreadHandle == NULL) {
        holler("doexec: failed to create WriteShell session thread, error = %s",
					(const char *)GetLastErrorAsString().c_str());

        //
        // Reset the client pipe handle to indicate this session is disconnected
        //
        Session->ClientSocket = INVALID_SOCKET;

        TerminateThread(Session->ReadShellThreadHandle, 0);
        if (Session->ReadShellErrThreadHandle != NULL) TerminateThread(Session->ReadShellErrThreadHandle, 0); // BOZY 2019

        return(FALSE);
    }

    //
    // Wait for either thread or the shell process to finish
    //
		int nohandles = 3; // BOZY 2019 - provide for optional STDERR
		
    HandleArray[0] = Session->ReadShellThreadHandle;
    HandleArray[1] = Session->WriteShellThreadHandle;
		if (Session->ReadShellErrThreadHandle != NULL) { // BOZY 2019 - assign STDERR handle
			HandleArray[2] = Session->ReadShellErrThreadHandle;
			nohandles++;
		}
    HandleArray[nohandles-1] = Session->ProcessHandle;
	
    i = WaitForMultipleObjects(nohandles, HandleArray, FALSE, 0xffffffff);

#define TerminateThread(h, f) WaitForSingleObject(h, 250)	// BOZY 2019 - to prevent memory leak
#define TerminateProcess(h, f) WaitForSingleObject(h, 250) // ditto
		if (debugFlag && i != 1) fprintf(stderr,"doexec: WaitForMultipleObjects: %d\n", i);

		switch (i) {
		    case WAIT_OBJECT_0 + 0:
		      TerminateThread(Session->WriteShellThreadHandle, 0);
		      if (Session->ReadShellErrThreadHandle != NULL) TerminateThread(Session->ReadShellErrThreadHandle, 0); // BOZY 2019
		      TerminateProcess(Session->ProcessHandle, 1);
		      break;
		
		    case WAIT_OBJECT_0 + 1:
		      TerminateThread(Session->ReadShellThreadHandle, 0);
		      if (Session->ReadShellErrThreadHandle != NULL) TerminateThread(Session->ReadShellErrThreadHandle, 0); // BOZY 2019
		      TerminateProcess(Session->ProcessHandle, 1);
		      break;
		
		    // BOZY 2019 - process STDERR handle
		    case WAIT_OBJECT_0 + 2:
		      TerminateThread(Session->WriteShellThreadHandle, 0);
		      TerminateThread(Session->ReadShellThreadHandle, 0);
		      TerminateProcess(Session->ProcessHandle, 1);
		      break;
		
		    case WAIT_OBJECT_0 + 3:
		      TerminateThread(Session->WriteShellThreadHandle, 0);
		      TerminateThread(Session->ReadShellThreadHandle, 0);
		      if (Session->ReadShellErrThreadHandle != NULL) TerminateThread(Session->ReadShellErrThreadHandle, 0); // BOZY 2019
		      break;

		  default:
		      holler("doexec: WaitForMultipleObjects error: %s",
						(const char *)GetLastErrorAsString().c_str());
		
		      break;
    }

#undef TerminateThread // BOZY 2019
#undef TerminateProcess

    // Close my handles to the threads, the shell process, and the shell pipes
    // BOZY 2019 - no need to close, closed in calling routine
	  //shutdown(Session->ClientSocket, SD_BOTH);
  	//closesocket(Session->ClientSocket);
	
	  DisconnectNamedPipe(Session->ReadPipeHandle);
    CloseHandle(Session->ReadPipeHandle);
	  // BOZY 2019 - STDERR handle
	  if (Session->ReadErrPipeHandle) {
//	  	if (debugFlag) { fprintf(stderr, "[doexec] closing Session->ReadErrPipeHandle %d\n", Session->ReadErrPipeHandle); }
	  	DisconnectNamedPipe(Session->ReadErrPipeHandle);
    	CloseHandle(Session->ReadErrPipeHandle);
	  }

	  DisconnectNamedPipe(Session->WritePipeHandle);
    CloseHandle(Session->WritePipeHandle);


    CloseHandle(Session->ReadShellThreadHandle);
    if (Session->ReadShellErrThreadHandle != NULL) {
//    	if (debugFlag) { fprintf(stderr, "[doexec] closing Session->ReadShellErrThreadHandle %u\n", Session->ReadShellErrThreadHandle); }
    	CloseHandle(Session->ReadShellErrThreadHandle); // BOZY 2019
    }
    CloseHandle(Session->WriteShellThreadHandle);

    CloseHandle(Session->ProcessHandle);

    free(Session);

    return(TRUE);
}


// **********************************************************************
//
// StartShell
//
// Execs the shell with the specified handle as stdin, stdout/err
//
// Returns process handle or NULL on failure
//

static HANDLE
StartShell(
		char *pr00gie,
    HANDLE ShellStdinPipeHandle,
    HANDLE ShellStdoutPipeHandle,
    HANDLE ShellStderrPipeHandle
    )
{
    PROCESS_INFORMATION ProcessInformation;
    STARTUPINFO si;
    HANDLE ProcessHandle = NULL;

    //
    // Initialize process startup info
    //
    si.cb = sizeof(STARTUPINFO);
    si.lpReserved = NULL;
    si.lpTitle = NULL;
    si.lpDesktop = NULL;
    si.dwX = si.dwY = si.dwXSize = si.dwYSize = 0L;
    si.wShowWindow = SW_HIDE;
    si.lpReserved2 = NULL;
    si.cbReserved2 = 0;

    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;

    si.hStdInput  = ShellStdinPipeHandle;
    si.hStdOutput = ShellStdoutPipeHandle;
		if (ShellStderrPipeHandle != NULL) { // BOZY 2019 - if we have STDERR separate - assign it
			si.hStdError = ShellStderrPipeHandle;
		} else // otherwise same as STDOUT
    	DuplicateHandle(GetCurrentProcess(), ShellStdoutPipeHandle,
      	              GetCurrentProcess(), &si.hStdError,
        	            DUPLICATE_SAME_ACCESS, TRUE, 0);

    if (CreateProcess(NULL, pr00gie, NULL, NULL, TRUE, 0, NULL, NULL,
                      &si, &ProcessInformation))
    {
        ProcessHandle = ProcessInformation.hProcess;
        CloseHandle(ProcessInformation.hThread);
    }
    else 
        holler("StartShell: failed to CreateProcess, error = %s, cmd=%s",
					(const char *)GetLastErrorAsString().c_str(), pr00gie);


    return(ProcessHandle);
}


// **********************************************************************
// SessionReadShellThreadFn
//
// The read thread procedure. Reads from the pipe connected to the shell
// process, writes to the socket.
//

static VOID
SessionReadShellThreadFn(
    PSESSION_DATA Parameter
    )
{
    PSESSION_DATA Session = Parameter;
    BYTE    Buffer[BUFFER_SIZE];
//    BYTE    Buffer2[BUFFER_SIZE*2+30];
    DWORD   BytesRead;

		// this bogus peek is here because win32 won't let me close the pipe if it is
		// in waiting for input on a read.
    while (PeekNamedPipe(Session->ReadPipeHandle, Buffer, sizeof(Buffer),
                    &BytesRead, NULL, NULL))
    {
				//DWORD BufferCnt, BytesToWrite;
        //BYTE PrevChar = 0;

				if (BytesRead > 0)
				{
					ReadFile(Session->ReadPipeHandle, Buffer, sizeof(Buffer),
                    &BytesRead, NULL);
				}
				else
				{
					Sleep(30); // 50
					continue;
				}

        //
        // for Windows rshd there is no need to replace any naked LF's
        // with CR-LF pairs.
        //
 //       for (BufferCnt = 0, BytesToWrite = 0; BufferCnt < BytesRead; BufferCnt++) {
            //if (Buffer[BufferCnt] == '\n' && PrevChar != '\r')
            //    Buffer2[BytesToWrite++] = '\r';
 //           PrevChar = Buffer2[BytesToWrite++] = Buffer[BufferCnt];
   //     }

        if (send(Session->ClientSocket, (const char *)Buffer, BytesRead, 0) <= 0)
            break;
    }

    if (GetLastError() != ERROR_BROKEN_PIPE)
        holler("SessionReadShellThreadFn: exited, error = %s",
							(const char *)GetLastErrorAsString().c_str());
//    debug("SessionReadShellThreadFn: closing Session->ClientSocket...");
//    shutdown(Session->ClientSocket, SD_RECEIVE); // 2
//    closesocket(Session->ClientSocket);

//debug("*** SessionReadShellThreadFn: exit ***");
	ExitThread(0);
}

// **********************************************************************
// SessionReadShellErrThreadFn
// BOZY 2019
// The read thread procedure. Reads from the pipe connected to the shell
// process, writes to the STDERR socket.
//

static VOID
SessionReadShellErrThreadFn(
    PSESSION_DATA Parameter
    )
{
    PSESSION_DATA Session = Parameter;
    BYTE    Buffer[BUFFER_SIZE];
    BYTE    Buffer2[BUFFER_SIZE*2+30];
    DWORD   BytesRead;

	// this bogus peek is here because win32 won't let me close the pipe if it is
	// in waiting for input on a read.
    while (PeekNamedPipe(Session->ReadErrPipeHandle, Buffer, sizeof(Buffer),
                    &BytesRead, NULL, NULL))
    {
			DWORD BufferCnt, BytesToWrite;
        BYTE PrevChar = 0;

			if (BytesRead > 0)
			{
				ReadFile(Session->ReadErrPipeHandle, Buffer, sizeof(Buffer),
                    &BytesRead, NULL);
			}
			else
			{
				Sleep(30);
				continue;
			}

        //
        // for Windows rshd there is no need to replace any naked LF's
        // with CR-LF pairs.
        //
        //for (BufferCnt = 0, BytesToWrite = 0; BufferCnt < BytesRead; BufferCnt++) {
            //if (Buffer[BufferCnt] == '\n' && PrevChar != '\r')
            //    Buffer2[BytesToWrite++] = '\r';
          //  PrevChar = Buffer2[BytesToWrite++] = Buffer[BufferCnt];
        //}

    	if (send(Session->ClientSocketErr, (const char *)Buffer, BytesRead, 0) <= 0)
            break;
    }

    if (GetLastError() != ERROR_BROKEN_PIPE)
        holler("SessionReadShellErrThreadFn exited, error = %s",
					(const char *)GetLastErrorAsString().c_str());
//debug("*** SessionReadShellErrThreadFn exit ***");
	ExitThread(0);
}


// **********************************************************************
// SessionWriteShellThreadFn
//
// The write thread procedure. Reads from socket, writes to pipe connected
// to shell process.


static VOID
SessionWriteShellThreadFn(
    PSESSION_DATA Parameter
    )
{
    PSESSION_DATA Session = Parameter;
    BYTE    RecvBuffer[1];
    BYTE    Buffer[BUFFER_SIZE];
    DWORD   BytesWritten;
    DWORD   BufferCnt;

    BufferCnt = 0;

    //
    // Loop, reading one byte at a time from the socket.
    //
    while (recv(Session->ClientSocket, (char *)RecvBuffer, sizeof(RecvBuffer), 0) != 0) {

        Buffer[BufferCnt++] = RecvBuffer[0];
        //if (RecvBuffer[0] == '\r')
        //        Buffer[BufferCnt++] = '\n';


		// Trap exit as it causes problems
//		if (strnicmp((const char *)Buffer, "exit\r\n", 6) == 0)
//			ExitThread(0);


        //
        // If we got a CR, it's time to send what we've buffered up down to the
        // shell process.
        // SECURITY FIX: CW 12/27/04 Add BufferCnt size check.  If we hit end of buffer, flush it
        if (RecvBuffer[0] == '\n' || RecvBuffer[0] == '\r' || BufferCnt > BUFFER_SIZE-1) {
            if (! WriteFile(Session->WritePipeHandle, Buffer, BufferCnt,
                            &BytesWritten, NULL))
            {
                break;
            }
            BufferCnt = 0;
        }
    }
//debug("--->>> SessionWriteShellThreadFn exit <<<---");
	ExitThread(0);
}

#endif