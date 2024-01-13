#!/bin/bash
#siege -c 500 -b -t10S  http://localhost:8080
#siege -H "Connection: Keep-Alive" -c 500 -b -t10S  http://127.0.0.1:8080
siege -c 500 -b -t10S  https://localhost:8080
