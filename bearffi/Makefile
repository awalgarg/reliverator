all: libbearffi.a

libbearffi.a: bearffi.c brssl.c
	rm -f libbearffi.a
	cc -Wall -Werror -O2 -I../bearssl-0.6/inc -c bearffi.c
	cc -Wall -Werror -O2 -I../bearssl-0.6/inc -c brssl.c
	ar -rcs libbearffi.a bearffi.o brssl.o
