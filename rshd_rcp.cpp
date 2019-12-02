
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock.h>
#include "service.h"
#include <io.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <direct.h>

//
// Function Prototypes for rshd.cpp functions and global variables
//
int receive (SOCKET rshClient, char* buff, int blen);
void runCommand (SOCKET rshClient, SOCKET rshClientErr, char* comm);
void error (const char* message, int ex=1);
void debug (const char* message);

extern int debugFlag;
extern int client;
//
//
// This is the size of the buffer used with rcp
#define RCP_BUFFER_SIZE 8192
// This is a delay time in milliseconds to wait after sending an error
// condition to the remote hosts during an rcp
#define RCP_ERR_DELAY   1000


// 
// Function:  RcpReceive
// Purpose:  Several of the messages sent in the rcp protocol are single
//           byte ( 0x00 ) or are text messages terminated by a ('\n').
//           This routine reads the message a single byte at a time and
//           checks for the appropriate termination condition.
// Inputs:   rchClient - SOCKET for communicating to remote system
//           buff -  Buffer to hold the data.
//           blen -  length of the buffer.
// Outputs:  SOCKET_ERROR if recv fails
//           number of characters received on SUCCESS
// Assumptions:  None
// Comments:  None
//
int
RcpReceive( SOCKET rshClient, char*buff, int blen )
{
        int i;
        int rlen;
        char    tchar;

                i=0;
                buff[0] = 0; 
                do
                {
                        rlen=recv(rshClient, &buff[i], 1, 0);
                        if(rlen==SOCKET_ERROR)
                        {
                                error("Cannot receive client data.", 0);
                                return( rlen );
                        }
                        if(debugFlag)
                        {
                                if ( !rlen )
                                        fprintf(stderr, "[%d] ...got %d chars. \n", 
                                                client, rlen );
                                else
                                        fprintf(stderr, "[%d] ...got %d chars. [%c]\n", 
                                                client, rlen, buff[i] );
                        }
                        tchar = buff[i];
                        i+=1;
                        if ( i > blen )
                        {
                                // The buffer has overflowed
                                WSASetLastError( WSAEMSGSIZE );
                                return( SOCKET_ERROR );
                        }
                }       while( (tchar != '\n') && (tchar != 0) );

                return i;
}

// 
// Function:  ParseTarget
// Purpose:  ParseTarget is the first step in processing environment
//           variables and wild card characters that may exists in 
//           the target specification of the rcp command.  All
//           environment variables are expanded and a find is initiated
//           to handle the wild card characters ( & and * ).
// Iputs:    hFile - Pointer to a file handle.  The file handle is used
//                   by the calling process to obtain more files 
//                   associated with the target.
//           Target - This is the target file/directory that needs to 
//                    be expanded.
//           bDir - This flag will be set to TRUE if the TARGET is a
//                  directory and FALSE if it is a file.
// Outputs:  TRUE if there are possibly more files that match the target
//           FALSE if this is the only file that matches
// Assumptions:
//   The wildcard characters are only valid if used in the last item
//   in the path specified by Target.
// Comments:
//   None
// See Also:
//   NextTarget and CloseTarget
//
BOOL
ParseTarget( HANDLE* hFile, char* Target, BOOL* bDir )
{
        char    strPath[MAX_PATH];
        long    lLen;
        WIN32_FIND_DATA wfdFileData;
        BOOL    bMoreFiles = FALSE;
        char*   strLastSlash;
        char    strDirectory[MAX_PATH];
        struct _stat statbuf;

        // TARGET may contain:
        //     Environment Variables:  %name%
        //     Wild Card Characters: ? and *

        lLen = ExpandEnvironmentStrings( Target, strPath, MAX_PATH );
        
        if ( debugFlag )
                fprintf( stderr, "The expanded path is %d chars %d: %s\n", lLen,
                        GetLastError(), strPath );

        // Determine the directory name for the expanded target.
        strLastSlash = strchr( strPath, '/' );
        while ( strLastSlash != NULL )
        {
                *strLastSlash = '\\';
                strLastSlash++;
                strLastSlash=strrchr( strLastSlash, '/' );
        }
        
        strLastSlash = strrchr( strPath, '\\' );
        if ( (strLastSlash == NULL) || (strLastSlash==strPath) )
                strDirectory[0] = 0;
        else
        {
                strncpy( strDirectory, strPath, (long)(strLastSlash - strPath) );
                strDirectory[(long)(strLastSlash - strPath)] = 0;
                strcat( strDirectory, "\\" );
        }

        // If the target has wildcards, process them
        if ( (strchr( strPath, '?' ) != NULL) ||
                (strchr( strPath, '*' ) != NULL) )
        {
                *hFile = FindFirstFile( strPath, &wfdFileData );
                if( *hFile != INVALID_HANDLE_VALUE )
                {
                        bMoreFiles = TRUE;
                        if ( wfdFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY )
                        {
                                *bDir = TRUE;
                                // Ignore directories "." and ".."
                                while ( !(strcmp( wfdFileData.cFileName, ".")) ||
                                        !(strcmp( wfdFileData.cFileName, "..")) )
                                {
                                        if( !FindNextFile( *hFile, &wfdFileData ) )
                                        {
                                                // Handle error
                                                Target[0]=0;
                                                *bDir = FALSE;
                                                return FALSE;
                                        }
                                        if ( wfdFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY )
                                                *bDir = TRUE;
                                        else
                                                *bDir = FALSE;
                                }
                        }
                        else
                        {
                                *bDir = FALSE;
                        }

                        sprintf( Target, "%s%s", strDirectory, wfdFileData.cFileName );
                }
                else
                {
                        Target[0]=0;
                        *bDir = FALSE;
                        return FALSE;
                }
        }
        else
        {
                // Check to see if Target is a file or directory
                strcpy( Target, strPath );
                if ( _stat( Target, &statbuf ))
                {
                        return FALSE;
                }
                else
                {
                        if ( statbuf.st_mode & S_IFDIR )
                        {
                                *bDir = TRUE;
                        }
                        else
                                *bDir = FALSE;
                }
        }
        return(bMoreFiles);
}

//
// Function: NextTarget
// Purpose:  This function gets the next available target that matches
//           the specification passed to ParseTarget for the specified
//           HANDLE.  
// Inputs:   hFile - HANDLE returned from call to ParseTarget.
//           bDir - This flag will be set to TRUE if the TARGET is a
//                  directory and FALSE if it is a file.
// Outputs:  NULL - If no more matches exist.
//           Pointer to target name if a match is found.
// Assumptions: 
//   The pointer returned by NextTarget should never be deleted.
//   NextTarget is always called after ParseTarget.
//   No target names will be larger than MAX_PATH.
// Comments: None
// See Also:  ParseTarget, CloseTarget.
//
char* 
NextTarget( HANDLE hFile, BOOL* bDir )
{
        static char Target[MAX_PATH];
        WIN32_FIND_DATA wfdFileData;

        // Make sure the handle is not bad.
        if( hFile == INVALID_HANDLE_VALUE )
        {
                *bDir = FALSE;
                return NULL;
        }

        if( FindNextFile( hFile, &wfdFileData ) )
        {
                // A match was found
                if ( wfdFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY )
                {
                        *bDir = TRUE;
                        // Ignore directories "." and ".."
                        while ( !(strcmp( wfdFileData.cFileName, ".")) ||
                                !(strcmp( wfdFileData.cFileName, "..")) )
                        {
                                if( !FindNextFile( hFile, &wfdFileData ) )
                                {
                                        // Handle error
                                        Target[0]=0;
                                        *bDir = FALSE;
                                        return NULL;
                                }
                                if ( wfdFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY )
                                        *bDir = TRUE;
                                else
                                        *bDir = FALSE;
                        }
                }
                else
                {
                        *bDir = FALSE;
                }

                sprintf( Target, "%s", wfdFileData.cFileName );
        }
        else
        {
                Target[0]=0;
                *bDir = FALSE;
                return NULL;
        }
        return( Target );
}

// 
// Function: CloseTarget
// Purpose:  Terminates the search for target matches that was initiated
//           in the call to ParseTarget.
// Inputs:   hFile - HANDLE returned from call to ParseTarget.
// Outputs:  None
// Assumptions:  
//   CloseTarget must always be used to close the find initiated by
//   ParseTarget.
//   There are no more matches to a target when NextTarget returns a
//   NULL.
// Comments:  None
// See Also:  ParseTarget, NextTarget.
void
CloseTarget( HANDLE hFile )
{
        if( hFile != INVALID_HANDLE_VALUE )
        {
                FindClose( hFile );
        }
        return;
}

//
// Function: RcpSvrSend
// Purpose:  This functions processes an rcp request to send files to 
//           a remote system.
// Inputs:   rshClient - SOCKET used for communication to the remote
//                       system.
//           Target - The target specified in the rcp request
//           bRecursive - This request must recurse the sub-directories
//                        of the specfied target
// Outputs:  None
// Assumptions:  
//   All files sent are read as BINARY files.  This prevents 
//   the translation of CR-LF to LF and preserves the size of the file 
//   and the data contained in it.
// Comments:
//
void
RcpSvrSend( SOCKET rshClient, char* Target, BOOL bRecursive )
{
        char    buff[RCP_BUFFER_SIZE+1];
        int             blen=RCP_BUFFER_SIZE;
        int             FileId;
        int             nFileSize;
        int     nBytesRead;
        int             nBytesSent;
        int             dwBytes;
        int             nValue;
        BOOL    bMoreFiles;
        HANDLE  hFile = INVALID_HANDLE_VALUE;
        char    expTarget[MAX_PATH];
        char*   Target2;
        char*   FileName;
        BOOL    bDir;
        BOOL    bTarget;
        BOOL    bProcessing;
        struct _stat statbuf;

        // Copy the target to a buffer we know will hold MAX_PATH
        strcpy( expTarget, Target );
        // Check the target for environment variables and wild cards
        bMoreFiles = ParseTarget( &hFile, expTarget, &bDir );
        bTarget = bDir;

        if ( !bRecursive & bDir )
        {
                // Error condition
                buff[0]=1;
                sprintf( &buff[1], "rcp:  %s: Not a plain file\n",expTarget);
                if(send(rshClient, buff, strlen( &buff[1])+1, 0) < 1)
                {
                        error("Error sending result status.", 0);
                }
                Sleep( RCP_ERR_DELAY );
                if ( bMoreFiles )
                        CloseTarget( hFile );
                return;
        }
        if ( _access(expTarget, 02 ) )
        {
                // Error condition
                buff[0]=1;
                if ( errno == ENOENT )
                        sprintf( &buff[1], "rcp: %s: No such file or directory\n",
                                expTarget );
                else
                        sprintf( &buff[1], "rcp: %s: Permission Denied\n", expTarget);
                if(send(rshClient, buff, strlen( &buff[1])+1 , 0) < 1)
                {
                        error("Error sending result status.", 0);
                }
                Sleep( RCP_ERR_DELAY );
                if ( bMoreFiles )
                        CloseTarget( hFile );
                return;
        }
        // receive data from the client expecting 0x00
        if((dwBytes = RcpReceive(rshClient, buff, blen))==SOCKET_ERROR)
        {
                error("Cannot receive client data.", 0);
                if ( bMoreFiles )
                        CloseTarget( hFile );
                return;
        }
        
        if ( buff[0] != 0 )
        {
                error("Remote system failed." ,0 );
                if ( bMoreFiles )
                        CloseTarget( hFile );
                return;
        }

        bProcessing = TRUE;
        Target2 = expTarget;
        while( Target2 != NULL )
        {
                if( bDir )
                {
                        // notify remote system to create a directory
                        FileName = strrchr( Target2, '\\' );
                        if ( FileName == NULL )
                                FileName = Target2;
                        else
                                FileName++;
        
                        sprintf( buff, "D0755 0 %s\n", FileName );
                
                        if(send(rshClient, buff, strlen(buff), 0) < 1)
                        {
                                error("Error sending directory status.", 0);
                                if ( bMoreFiles )
                                        CloseTarget( hFile );
                                return;                 
                        }       
        
                        
                        _chdir( Target2 );
                        RcpSvrSend( rshClient, (char *) "*", bRecursive );
                        _chdir( ".." );
                }
                else
                {
                        FileName = strrchr( Target2, '\\' );
                        if ( FileName == NULL )
                                FileName = Target2;
                        else
                        {
                                *FileName = 0;
                                _chdir( Target2 );
                                FileName++;
                        }
                        // Open the file for reading 
                        FileId = _open( FileName , _O_RDONLY|_O_BINARY, _S_IWRITE );
                        if ( FileId == -1 )
                        {
                                // Error condition
                                buff[0]=1;
                                sprintf( &buff[1], "rcp: %s: Cannot open file\n",
                                        FileName );
                                if(send(rshClient, buff, strlen( &buff[1])+1, 0) < 1)
                                {
                                        error("Error sending result status.", 0);
                                }
                                Sleep( RCP_ERR_DELAY );
                                if ( bMoreFiles )
                                        CloseTarget( hFile );
                                return;
                        }
                        else
                        {
                                // Notify remote system to create a file
                                nValue = _fstat( FileId, &statbuf );
                                nFileSize = statbuf.st_size;
                                sprintf( buff, "C0644 %d %s\n", nFileSize, FileName );
                                if(send(rshClient, buff, strlen(buff), 0) < 1)
                                {
                                        error("Error sending result status.", 0);
                                        _close( FileId );
                                        if ( bMoreFiles )
                                                CloseTarget( hFile );
                                        return;                 
                                }

                                // receive data from the client expecting 0x00
                                if((dwBytes = RcpReceive(rshClient, buff, blen))==SOCKET_ERROR)
                                {
                                        error("Cannot receive client data.", 0);
                                        _close( FileId );
                                        if ( bMoreFiles )
                                                CloseTarget( hFile );
                                        return;
                                }
                                if ( buff[0] != 0 )
                                {
                                        error("Remote system Failed.", 0);
                                        _close( FileId );
                                        if ( bMoreFiles )
                                                CloseTarget( hFile );
                                        return;
                                }

                                // Process the contents of the file
                                nBytesSent = 0;
                                while( nBytesSent < nFileSize )
                                {
                                        // read the file
                                        nBytesRead = read( FileId, buff, blen );
                                        if ( nBytesRead <= 0 )
                                        {
                                                // Error condition
                                                buff[0]=1;
                                                sprintf( &buff[1], "rcp: %s: Cannot read source\n",
                                                        FileName );
                                                if(send(rshClient, buff, strlen( &buff[1])+1, 0) < 1)
                                                {
                                                        error("Error sending result status.", 0);
                                                }
                                                _close( FileId );
                                                Sleep( RCP_ERR_DELAY );
                                                if ( bMoreFiles )
                                                        CloseTarget( hFile );
                                                return;                 
                                        }
        
                                        nBytesSent+=nBytesRead;
                                        if(send(rshClient, buff, nBytesRead, 0) < 1)
                                        {
                                                error("Error sending file.", 0);
                                                _close( FileId );
                                                if ( bMoreFiles )
                                                        CloseTarget( hFile );
                                                return;                 
                                        }
                                }

                                _close( FileId );
        
                                buff[0]=0;
                                if(send(rshClient, buff, 1, 0) < 1)
                                {
                                        error("Error sending file termination.", 0);
                                        if ( bMoreFiles )
                                                CloseTarget( hFile );
                                        return;                 
                                }
        
                        }

                        // receive data from the client expecting 0x00
                        if((dwBytes = RcpReceive(rshClient, buff, blen))==SOCKET_ERROR)
                        {
                                error("Cannot receive client data.", 0);
                                if ( bMoreFiles )
                                        CloseTarget( hFile );
                                return;
                        }
                        if ( buff[0] != 0 )
                        {
                                error("Remote system failed.", 0);
                                if ( bMoreFiles )
                                        CloseTarget( hFile );
                                return;
                        }

                }

                Target2 = NextTarget( hFile, &bDir );
                if (Target2 == NULL )
                        CloseTarget( hFile );
        }

        if ( bRecursive )
        {
                // Recursive sends are closed by sending "E\n"
                sprintf(buff, "E\n" );
                if(send(rshClient, buff, strlen(buff), 0) < 1)
                {
                        error("Error sending directory status.", 0);
                        return;                 
                }               
 
                // receive data from the client 
                if((dwBytes = RcpReceive(rshClient, buff, blen))==SOCKET_ERROR)
                {
                        error("Cannot receive client data.", 0);
                        return;
                }
                if ( buff[0] != 0 )
                {
                        error("Remote system Failed.", 0);
                        return;
                }

        }

}

//
// Function: RcpSvrRecv
// Purpose:  Process files being sent by a remote system to the 
//           system on which rshd is running.
// Inputs:   rshClient - SOCKET used for communication to the remote
//                       system.
//           Target - The target specified in the rcp request
//           bRecursive - This request recurses sub-directories on the
//                        remote system. directories may need to be
//                        created.
//           bTargDir - The target specified MUST be a directory.
// Outputs:  None
// Assumptions:
//    All files are written as BINARY to preserver the file size and
//    data contained in the files.  
// Comments:
//
void
RcpSvrRecv( SOCKET rshClient, char* Target, BOOL bRecursive, 
                   BOOL bTargDir)
{
        char    buff[RCP_BUFFER_SIZE+1];
        int             blen=RCP_BUFFER_SIZE;
        int             FileId;
        DWORD   dwFileSize;
        DWORD   dwBytesRecv;
        int             dwBytes;
        int             nValue;
        BOOL    bMoreFiles;
        HANDLE  hFile = INVALID_HANDLE_VALUE;
        char    expTarget[MAX_PATH];
        char*   Target2;
        char*   NewLine;
        BOOL    bDir;
        BOOL    bTarget;
        BOOL    bProcessing;

        strcpy( expTarget, Target );
        bDir = bTargDir;
        bMoreFiles = ParseTarget( &hFile, expTarget, &bDir );
        if ( bMoreFiles )
        {
                Target2 = NextTarget( hFile, &bTarget );
                if ( Target2 != NULL )
                {
                        // Error condition:  more than one target
                        buff[0]=1;
                        sprintf( &buff[1], "rcp:  ambiguous target\n");
                        if(send(rshClient, buff, strlen( &buff[1])+1, 0) < 1)
                        {
                                error("Error sending result status.", 0);
                        }
                        Sleep( RCP_ERR_DELAY );
                        CloseTarget( hFile );
                        return;
                }
        }
        CloseTarget( hFile );
        bTarget = bDir;

        if ( bTargDir & !bDir )
        {
                // Error condition:  Directory required but file specified
                buff[0]=1;
                sprintf( &buff[1], "rcp:  %s: Not a directory\n",expTarget);
                if(send(rshClient, buff, strlen( &buff[1])+1, 0) < 1)
                {
                        error("Error sending result status.", 0);
                }
                Sleep( RCP_ERR_DELAY );
                return;
        }

        if ( _access(expTarget, 02 ) )
        {
                if ( bDir || (!bDir && ( errno != ENOENT )) )
                {
                        // Error condition:  Can't access the target  
                        buff[0]=1;
                        if ( bDir && (errno == ENOENT) )
                                sprintf( &buff[1], "rcp: %s: No such file or directory\n",
                                        expTarget );
                        else
                                sprintf( &buff[1], "rcp: %s: Permission Denied\n",
                                        expTarget );
                        if(send(rshClient, buff, strlen( &buff[1])+1, 0) < 1)
                        {
                                error("Error sending result status.", 0);
                        }
                        Sleep( RCP_ERR_DELAY );
                        return;
                }
        }

        bProcessing = TRUE;
        Target2 = expTarget;

        // Process files/directories from the remote system
        while( bProcessing )
        {
                debug("Sending null byte ...");
            buff[0]=0;
                if(send(rshClient, buff, 1, 0) < 1)
                {
                        error("Error sending result status.", 0);
                        return;
                }
    
                if ( bDir )
                {
                        nValue = _chdir( Target2 );
                        if ( nValue == -1 )
                        {
                                // Error condition
                                buff[0]=1;
                                sprintf( &buff[1], "rcp: %s: No such file or directory\n",
                                        expTarget );
                                if(send(rshClient, buff, strlen( &buff[1])+1, 0) < 1)
                                {
                                        error("Error sending result status.", 0);
                                }
                                Sleep( RCP_ERR_DELAY );
                                return;
                        }
                }

                // receive data from the client 
                // File/dir  specification ends in a '\n', so read byte by byte
                // until one is reached or a '0' is received
                if((dwBytes = RcpReceive(rshClient, buff, blen))==SOCKET_ERROR)
                {
                        error("Cannot receive client data.", 0);
                        return;
                }
                
                // Process the file or directory specification
                switch ( buff[0] )
                {
                case 0:
                case 1:
                        // Finished processing
                        return;
                        break;

                case 'E':
                        // Finished with current directory. Backup to the 
                        // parent directory.
                        Target2 = (char *) "..";
                        bDir = TRUE;
                        continue;
                        break;

                case 'T':
                        // This is permissions data related to the -p option.
                        // Just ignore it.
                        continue;
                        break;

                case 'D':
                        // A directory is being identified
                        bDir = TRUE;
                        Target2 = strtok( buff, " " );
                        Target2 = strtok( NULL, " " );
                        Target2 = strtok( NULL, " " );
                        NewLine = strchr( Target2, 0x0a );
                        *NewLine = 0;
                        strcpy( expTarget, Target2 );
                        Target2 = expTarget;

                        if ( _access(Target2, 02 ) )
                        {
                                if ( errno != ENOENT )
                                {
                                        // Error condition:  Can't access directory
                                        buff[0]=1;
                                        sprintf( &buff[1], "rcp: %s: Directory access failure %d\n",
                                                        expTarget, errno );
                                        if(send(rshClient, buff, strlen( &buff[1])+1, 0) < 1)
                                        {
                                                error("Error sending result status.", 0);
                                        }
                                        Sleep( RCP_ERR_DELAY );
                                        return;
                                }
                                // Create directory 
                                nValue = _mkdir( Target2 );
                                if ( nValue == -1 )
                                {
                                        // Error condition:  Can't create directory
                                        buff[0]=1;
                                        sprintf( &buff[1], "rcp: %s: Directory creation failed\n",
                                                expTarget );
                                        if(send(rshClient, buff, strlen( &buff[1])+1, 0) < 1)
                                        {
                                                error("Error sending result status.", 0);
                                        }
                                        Sleep( RCP_ERR_DELAY );
                                        return;
                                }
                        }
                        continue;
                        break;

                case 'C':
                        // A file  is being identified
                        if ( bTarget )
                        {
                                Target2 = strtok( buff, " " );
                                Target2 = strtok( NULL, " " );
                                Target2 = strtok( NULL, " " );
                                NewLine = strchr( Target2, 0x0a );
                                *NewLine = 0;
                                strcpy( expTarget, Target2 );
                                Target2 = expTarget;
                        }

                        bDir = FALSE;
                        // Open the file for writing 
                        FileId = _open( Target2, _O_WRONLY|_O_TRUNC|_O_CREAT|_O_BINARY, _S_IWRITE );
                        if ( FileId == -1 )
                        {
                                // Error condition
                                buff[0]=1;
                                sprintf( &buff[1], "rcp: %s :Cannot open file\n", Target2);
                                if(send(rshClient, buff, strlen( &buff[1])+1, 0) < 1)
                                {
                                        error("Error sending result status.", 0);
                                }
                                Sleep( RCP_ERR_DELAY );
                                return;
                        }
                        break;

                default:
                        return;
                }

                dwFileSize = atol( &buff[6] );
                if(debugFlag)
                        fprintf(stderr, "Receiving file %s of size %d.\n", Target2, dwFileSize );

                buff[0]=0;
                if(send(rshClient, buff, 1, 0) < 1)
                {
                        error("Error sending result status.", 0);
                        _close( FileId );
                        return;
                }

                // Process the file being transferred.
                dwBytesRecv=0;
                // If file size=0, expect 1 byte 0x00 
                if( dwFileSize == 0 )
                {
                        if((dwBytes = RcpReceive(rshClient, buff, blen )) == SOCKET_ERROR)
                        {
                                error("Cannot receive client data.", 0);
                                _close( FileId );
                                return;
                        }
                        else
                                if ( buff[0] != 0 )
                        {
                                error( "Received data for zero length file",0);
                        }
                }
                else 
                {
                        while( dwBytesRecv != dwFileSize )
                        {
                                // receive data from the client 
                                if((dwBytes = receive(rshClient, buff, blen))==SOCKET_ERROR)
                                {
                                        error("Cannot receive client data.", 0);
                                        _close( FileId );
                                        return;
                                }

                                if ( dwBytes < blen )
                                        dwBytes--;

                                dwBytesRecv += dwBytes;

                                // write the data to the file
                                nValue = write( FileId, buff, dwBytes );
        
                                if ( nValue != dwBytes )
                                {
                                        // Error condition:  write failure
                                        buff[0]=1;
                                        sprintf( &buff[1], "rcp: %s :Cannot write to file\n",
                                                Target2 );
                                        if(send(rshClient, buff, strlen( &buff[1])+1, 0) < 1)
                                        {
                                                error("Error writing error status.", 0);
                                        }
                                        Sleep( RCP_ERR_DELAY );
                                        _close( FileId );
                                        return;
                                }
                        }
                }

                _close( FileId );
        }
    
        return;
}

//
// Function: rcpCommand
// Purpose:  Parses the command passed to rshd to determine if it
//           is a rcp request.  Determines what type of rcp is being
//           requested and processes it accordingly.
// Inputs:   rshClient - SOCKET for communicating to the remote system
//           rchClientErr - possible 2nd SOCKET for communication.
//           Cmd - Command passed to rshd to be validated.
// Outputs:  None
// Assumptions:
//    Valid rcp requests are in the form:
//         rcp -t [-d] [-r] [-p] target 
//         rcp -f [r] [-p] target
//    NOTE:  The -p option is being ignored since there is not a good
//           correlation between UNIX and NT when it comes to file
//           permissions and ownership.
// Comments:
// 
void
rcpCommand(SOCKET rshClient, SOCKET& rshClientErr, char* Cmd )
{
        char* arg;
        char* HomeDir;
        int offset;
        BOOL    bTargDir = FALSE;
        BOOL    bSvrRecv = FALSE;
        BOOL    bSvrSend = FALSE;
        BOOL    bRecursive = FALSE;

        // Get the current working directory
        HomeDir = _getcwd( NULL, MAX_PATH);

        offset = 4;

        arg = &Cmd[offset];

        while( *arg == '-' )
        {
                switch( arg[1] )
                {
                case 'd':  // Target must be directory
                        bTargDir = TRUE;
                        break;

                case 't':  // RSHD is receiving files
                        bSvrRecv = TRUE;
                        break;

                case 'f':  // RSHD is sending files
                        bSvrSend = TRUE;
                        break;

                case 'p':  // Preserve Permissions
                        // This option is ignored for now
                        break;

                case 'r':  // Recursive send/recv
                        bRecursive = TRUE;
                        break;

                default:
                        // This is not an attempt to rcp, use runCommand
                        runCommand( rshClient, rshClientErr, Cmd );
                        return;
                }

                offset += 3;
                arg = &Cmd[offset];
        }

        if ( !bSvrRecv && !bSvrSend )
        {
                // This is not a valid attempt to rcp, use runCommand.
                runCommand( rshClient, rshClientErr, Cmd );
                return;
        }

        if ( bSvrRecv )
        {
                if ( bRecursive )
                        bTargDir = TRUE;

                RcpSvrRecv( rshClient, arg, bRecursive, bTargDir );
        }
        else // must be bSvrSend
        {
                RcpSvrSend( rshClient, arg, bRecursive );
        }

        // Make sure we end up where we started.
        _chdir( HomeDir );
        free( HomeDir );
        return;
}

