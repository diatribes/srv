#!/bin/bash
echo -n -e 'GET / HTTP/1.1\r\n\r\n' | nc localhost 8080

