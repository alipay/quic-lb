TARGET  := liblbtest.so

#compile and lib parameter
#编译参数
CC      := gcc
LIBS    :=
LDFLAGS := -L../libs/openssl  -lssl -lcrypto  -ldl
DEFINES :=
INCLUDE := -I.
CFLAGS  := -g -Wall -O3 $(DEFINES) $(INCLUDE) -fPIC
CXXFLAGS:= $(CFLAGS) -DHAVE_CONFIG_H
SHARE   := -fPIC -shared -o

SOURCE  := $(wildcard *.c) $(wildcard *.cpp)
OBJS    := $(patsubst %.c,%.o,$(patsubst %.cpp,%.o,$(SOURCE)))

.PHONY : everything objs clean veryclean rebuild

everything : $(TARGET)

all : $(TARGET)

objs : $(OBJS)

build : $(TARGET)

test :
	make build
	pytest *.py

rebuild: veryclean everything

clean :
	rm -fr *.o
	rm -fr *.so

veryclean : clean
	rm -fr $(TARGET)

$(TARGET) : $(OBJS)
	$(CC) $(CXXFLAGS) $(SHARE) $@ $(OBJS) $(LDFLAGS) $(LIBS)
