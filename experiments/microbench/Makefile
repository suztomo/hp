T_OPEN=opentest
T_CONNECT=connecttest
T_UNAME=unametest
TARGET_TXT=test.txt
VDIR=/j/00001/home/suzuki/
GCC=gcc

all: $(T_OPEN) $(T_CONNECT) $(T_UNAME)
	chmod 755 $(T_OPEN) $(T_CONNECT)

$(T_OPEN): $(T_OPEN).c
	$(GCC) -Wall $@.c -o $@ -ggdb

$(T_CONNECT): $(T_CONNECT).c
	$(GCC) -Wall $@.c -o $@ -ggdb

$(T_UNAME): $(T_UNAME).c
	$(GCC) -Wall $@.c -o $@ -ggdb

clean:
	rm $(T_OPEN) $(T_CONNECT) $(T_UNAME)

run:
	./$(T_OPEN)
	./$(T_CONNECT) 127.0.0.1 11111
	./$(T_UNAME)
	cp -r ./ $(VDIR)
