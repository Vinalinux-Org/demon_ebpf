# Compiler và flag
CC          := cc
CFLAGS      := -O2 -g -Wall -Wextra
INCLUDES    := -I../ebpf/include -I$(HOME)/bpftool/libbpf/include/uapi -I$(HOME)/bpftool/libbpf/include

# Thư viện libbpf static và các lib phụ trợ
LIBBPF_DIR  := $(HOME)/bpftool/libbpf/src
LIBBPF_A    := $(LIBBPF_DIR)/libbpf.a
LIBS        := $(LIBBPF_A) -lelf -lz -lcurl

# Đầu ra
OUT_DIR     := dist
TARGET      := $(OUT_DIR)/collector
SRC         := collector.c

# Rule mặc định
all: $(TARGET)

$(TARGET): $(SRC)
	mkdir -p $(OUT_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) $(SRC) -o $(TARGET) $(LIBS)

clean:
	rm -rf $(OUT_DIR)
