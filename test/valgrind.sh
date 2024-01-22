#!/bin/sh
valgrind -v --leak-check=full --show-leak-kinds=all --tool=memcheck ../srv mv 8080 ../docroot

