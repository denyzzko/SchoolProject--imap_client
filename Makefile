CC = gcc
CFLAGS = -Wall -Wextra -Werror -pedantic -std=c99

TARGET = imapcl
SRCDIR = src
INCLUDEDIR = include

SRCS = $(SRCDIR)/main.c $(SRCDIR)/parser.c $(SRCDIR)/connection.c $(SRCDIR)/communication.c
OBJS = $(SRCS:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS) -lssl -lcrypto

clean:
	rm -f $(TARGET) $(OBJS)
