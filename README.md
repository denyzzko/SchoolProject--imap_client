# IMAP Email Client

This project is a simple command-line email client written in C. It connects to an IMAP server, authenticates the user, and retrieves emails over a secure (TLS) or insecure connection.

## Description

The client communicates with an IMAP4rev1 server using TCP sockets. It supports secure connections using OpenSSL and allows users to retrieve and parse email headers and bodies from their inbox. 

The program demonstrates low-level socket programming, SSL/TLS communication, and protocol parsing.

## Features

- Connects to IMAP servers using plain TCP or SSL (via STARTTLS or implicit TLS)
- Supports login authentication
- Parses IMAP responses to retrieve messages
- Handles communication using dynamic buffers
- Modular structure with parser, connection, and communication components

### Requirements

- `gcc`
- `make`
- `libssl-dev` (OpenSSL)

### Compilation

```bash
make
```

### Example Usage

```bash
./imap_client -h imap.example.com -p 993 -s -l auth_file
```

- `-h` – IMAP server hostname
- `-p` – Port (e.g., 993 for IMAPS)
- `-s` – Use SSL/TLS
- `-l` – File containing login credentials

## Files

- `src/` – C source code (main logic, parser, connection handling, communication)
- `auth_file` – Example credentials file
- `Makefile` – Build instructions
