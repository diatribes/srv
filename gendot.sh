#!/bin/sh
gprof ./srv docroot/gmon.out | gprof2dot | dot -Tpng -o output.png
