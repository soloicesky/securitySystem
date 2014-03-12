
#CAROSSROOT:=/home/soloicesky/developementTools/arm/usr/bin
#CAROSSROOT:=
#CC:= $(CAROSSROOT)/arm-linux-gcc
CC:= gcc
AR:= ar
CFLAGS:= -shared -fPIC -Wall -g
SRC = $(wildcard sources/*.c)
OBJS = $(SRC:.c=.o)

PROJECTNAME := PCI

INCDIR = ./INC

LIBDIR := ./libs

TARGET = libPci.so
MAIN = testMain

all:$(OBJS)
	$(CC) -shared $(OBJS) -o $(TARGET) -L$(LIBDIR) -lUtils -lCrypto

	$(CC) $(OBJS) -o $(MAIN) -L$(LIBDIR) -lUtils -lCrypto
$(OBJS):%.o:%.c
	$(CC) $(CFLAGS) -c $< -o $@ -I$(INCDIR)

########################################################################################
#make lib
########################################################################################

TARGETLIB := libpci.a

slib:
	 $(AR) -cr $(TARGETLIB) SRC/*.o


########################################################################################
#copy to the  release directory
########################################################################################

RELEASEDIR := $(SOLOICESKYDIR)/$(PROJECTNAME)/realease
	 
release:
	cp -rf $(TARGETLIB) $(RELEASEDIR)/libs/static
	cp -rf SRC/*.h $(RELEASEDIR)/includes
	cp -rf SRC/*.h $(INCDIR)
clean:
	rm $(OBJS) $(TARGET)
