# Compiler và flag
CC          := cc
CFLAGS      := -O2 -g -Wall -Wextra
INCLUDES    := -I../ebpf/include -I$(HOME)/bpftool/libbpf/include/uapi -I$(HOME)/bpftool/libbpf/include

# Thư viện libbpf static và các lib phụ trợ
LIBBPF_DIR  := $(HOME)/bpftool/libbpf/src
LIBBPF_A    := $(LIBBPF_DIR)/libbpf.a
LIBS        := $(LIBBPF_A) -lelf -lz -lcurl -lpthread

# Đầu ra
OUT_DIR     := dist
TARGET      := $(OUT_DIR)/collector

# Source files
SRC         := main.c collector_core/collector_core.c queue/queue.c json_builder/json_builder.c time_utils/time_utils.c

# Object files
OBJ         := $(SRC:.c=.o)

# Rule mặc định
all: $(TARGET)

$(TARGET): $(OBJ)
	mkdir -p $(OUT_DIR)
	$(CC) $(CFLAGS) $(OBJ) -o $(TARGET) $(LIBS)

# Rule build object
%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

clean:
	rm -rf $(OUT_DIR) *.o queue/*.o collector_core/*.o json_builder/*.o time_utils/*.o
