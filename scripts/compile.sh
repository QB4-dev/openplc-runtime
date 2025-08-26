#!/bin/bash
set -euo pipefail

libPATH="core/generated/plc_lib/lib"
srcPATH="core/generated/plc_lib"
FLAGS="-pedantic -Wextra -fstack-protector-strong -D_FORTIFY_SOURCE=2 -O3 -Wformat -Werror=format-security -fPIC -fPIE"

# Compile objects
gcc $FLAGS -I "$libPATH" -c "$srcPATH/Config0.c" -o Config0.o
gcc $FLAGS -I "$libPATH" -c "$srcPATH/Res0.c"    -o Res0.o
gcc $FLAGS -I "$libPATH" -c "$srcPATH/debug.c"   -o debug.o
gcc $FLAGS -I "$libPATH" -c glueVars.c           -o glueVars.o

# Link shared library
gcc $FLAGS -shared -o libplc.so Config0.o Res0.o debug.o glueVars.o

# Move result
mv libplc.so ..
rm *.o
