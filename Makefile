OBJS = rshd.o rshd_rcp.o Service.o doexec.o resource.o
LIBS = -ladvapi32 -luser32 -lws2_32 
# was: -lwsock32
CPPFLAGS=-O  -ggdb -fno-inline -fno-omit-frame-pointer
CFLAGS=-O

.cpp.o:
	g++ $(CPPFLAGS) -c -DGAPING_SECURITY_HOLE $<

.c.o:
	gcc $(CFLAGS) -c -DGAPING_SECURITY_HOLE $<

all: rshd.exe

clean:
	del $(OBJS)

rshd.exe: $(OBJS) Makefile
	g++ $(CPPFLAGS) -o rshd.exe $(OBJS) $(LIBS)
#	link /nologo /subsystem:console $(OBJS) $(LIBS)

resource.o:	resource.rc
	windres resource.rc -o resource.o


# EOF