This is RSH daemon for Windows (yet another attempt)

Initial code was taken from https://sourceforge.net/projects/rshd/

Merged with code from:

1) https://github.com/VladislavShcherba/RSHD/

Mostly changes to rshd.c - user / host authorization processing in single sub.

2) https://github.com/diegocr/netcat

Took doexec.c and modified it to accommodate for separate stderr processing (by
creating 3rd reader thread) + removed CRLF processing on stdout.

============================================================

Compiles almost clean and builds OK with "gcc version 8.3.0 (x86_64-posix-seh,
Built by strawberryperl.com project", Target: x86_64-w64-mingw32 using supplied
Makefile. I got no Microsoft development tools and not planning to use any.

============================================================

Why change?

Initial rshd version used system() with redirection to files, then dumped
results to stdout, therefore unable to run interactive console programs. This
version redirects stdin / stdout and stderr (if port is supplied by client -
standard Windows rsh.exe does NOT do it) to cient sockets using Windows pipes.
When using with interactive programs - do not forget to set autoflush in the
program that runs using rshd (for perl scripts, do '$|=1;').

I did not provide an extra option to exhibit original behavior (could be useful
if you only run standard command prompt commands), but all routines are left
intact should you need this. Cannot say if this can be solved simply with
bat/cmd files, but, apparently, stdio redirection does not work well when using
CreateProcess() to run batch files.

Notes.

There is a somewhat ugly mapcommand() routine which I did for my own purpose. It
should not affect anything as it is now.

I believe I managed to get rid of accumulating open ports in TIME_WAIT state
(those connected to client stderr socket). shutdown() function parameter changed
to SD_RECEIVE, SO_LINGER set to 0 before shutting the socket down (BSD hack).

Replaced TerminateThread() calls with WaitForSingleObject() in doexec(),
avoiding stack corruption and data loss in client's stdout/stderr socket.

Tested with Windows / Linux / AIX versions of rsh client + my own rsh client
written in Microsoft Excel VBA.

Suspect some static vars in doexec.c and rshd.c may not be thread safe, but did
not encounter any issues so far.

Strongly suggest to read original readme document (supplied with this source
tree as original-readme.htm).

Enjoy.


TODO:

holler() function in doexec.cpp should be replaced with something more sane. For
now just changed to proper varargs.

Winsock error (cannot read initial data from client, past stderr socket data) at
511th (1022th and maybe every 511 calls afterwards) client connection still
exists, everything is fine on next connection. Cannot figure out what may be
primary cause of it - apparently some handles / descriptors are not being
closed. Must be related to some slot limits in C library. Maximum of 2048 thread
descriptors comes to mind, as I create 4 threads per client (including stderr
pipe thread). Maxtsdio got nothing to do with it - tried.
