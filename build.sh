#!/bin/bash

gcc -Wall -Wextra -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3 -O3 $(pkg-config --cflags --libs gtk+-3.0) -lgcrypt src/*.c -o otpclient_debug