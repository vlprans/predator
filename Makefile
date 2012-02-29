CXX=g++-local
CXXFLAGS= -c `libnet-config --cflags --defines` -ggdb
LDFLAGS=`libnet-config --libs` -lpthread -lpcap
OBJS=session.o predator.o common.o connection.o
PROG=predator

all: ${OBJS} 
	${CXX} ${LDFLAGS} -o ${PROG} ${OBJS}
	
session.o: session.cc session.h
	${CXX} ${CXXFLAGS} -o session.o session.cc

predator.o: predator.cc predator.h
	${CXX} ${CXXFLAGS} -o predator.o predator.cc

common.o: common.cc common.h
	${CXX} ${CXXFLAGS} -o common.o common.cc

connection.o: connection.cc connection.h
	${CXX} ${CXXFLAGS} -o connection.o connection.cc


clean:
	rm -f ${PROG} *.o *.core *~