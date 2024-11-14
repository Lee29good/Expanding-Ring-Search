# Makefile for traceroute-like ICMP program

CC = gcc
CFLAGS = -Wall -g
TARGET = ERS
SRC = ERS.c

# 目标: 编译目标
all: $(TARGET)

# 编译生成目标程序
$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC)

# 清理目标文件
clean:
	rm -f $(TARGET)

# 运行程序的目标
run: $(TARGET)
	./$(TARGET) $(ARGS)

.PHONY: all clean run
