CC = gcc
#CC = arm-none-linux-gnueabi-gcc


OPENSSL_DIR = ../openssl-1.0.1i
OPENSSL_INC = $(OPENSSL_DIR)/include/
OPENSSL_LIB = $(OPENSSL_DIR)         # $(OPENSSL_DIR)/libs/


SRC_DIR     = ./src
INCLUDE_DIR = ./include 
CFILES = $(wildcard $(SRC_DIR)/*.c)
OBJS   = $(CFILES:%.c=%.o)



CFLAGS  =  -O2
LDFLAGS =  -static  -lcrypto  #-lssl 
#LDFLAGS =  -Wl,-Bstatic  -lssl  -lcrypto  #-Wl,-Bdynamic  -ldl


TARGET = cert_tool
all : $(TARGET)

$(TARGET) : $(OBJS)
	$(CC)  $(CFLAGS)  $^  -o $(TARGET)  -L$(OPENSSL_LIB) $(LDFLAGS)

.c.o:
	$(CC)  $(CFLAGS) -c $^ -o $@  -I$(OPENSSL_INC)   -I$(INCLUDE_DIR) 

clean:
	rm -rf $(OBJS) $(TARGET) 
