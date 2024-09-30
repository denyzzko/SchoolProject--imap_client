CC = gcc
CFLAGS = -Wall -Wextra -Werror -pedantic -std=c99
TARGET = imapcl
SRCDIR = src
SRCS = $(SRCDIR)/main.c $(SRCDIR)/parser.c $(SRCDIR)/connection.c

OBJS = $(SRCS:.c=.o)

INCLUDES = -Iinclude
LIBS = -lssl -lcrypto

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(INCLUDES) -o $(TARGET) $(OBJS) $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

clean:
	rm -f $(TARGET) $(OBJS)