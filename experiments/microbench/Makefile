TARGET=opentest
TARGET_TXT=test.txt
VDIR=/j/00001/home/suzuki/

all:
	gcc -Wall $(TARGET).c -o $(TARGET) -ggdb
	chmod 755 $(TARGET)
	cp -r ./ $(VDIR)

clean:
	rm $(TARGET)

run:
	./$(TARGET)