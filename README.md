# eBPF Event Monitor - Dữ liệu Training cho AI

> File này dùng để train AI. Nếu bạn là AI, hãy bắt đầu đọc và hiểu source code thông qua giải thích trong file này.

## 1. Tổng quan

Dự án này triển khai hệ thống monitor sự kiện bằng eBPF trên Linux.  
Mục tiêu là quan sát các sự kiện của tiến trình user-space theo thời gian thực, gửi về collector, và lưu trữ để phân tích hoặc giám sát.

Hệ thống được chia thành 3 tầng:

1. **Module eBPF Kernel**
   - Hook vào các tracepoint kernel (`sys_enter_openat`, `sys_enter_read`, `sys_enter_write`).
   - Thu thập thông tin cơ bản của event (PID, TID, UID, cgroup, timestamp, fd, …).
   - Push event lên user-space qua **Ring Buffer**.

2. **Collector User-space**
   - Đăng ký callback để nhận event từ ring buffer eBPF.
   - Lọc bỏ các event không cần thiết.
   - Chuyển event thành JSON và enqueue vào queue nội bộ.
   - Gửi event tới server theo batch qua HTTP POST.

3. **Server**
   - Nhận mảng JSON từ collector qua HTTP.
   - Parse và enqueue vào queue nội bộ.
   - Ghi từng event thành một dòng JSON trong file log `events.log`.

## 2. Luồng hoạt động

### 2.1 Khởi tạo Collector
- Load object eBPF (`.bpf.o`) vào kernel.
- Attach chương trình vào tracepoint.
- Tạo ring buffer và callback.
- Khởi chạy thread xử lý và gửi event.

### 2.2 Collector → Server
- Khi có event từ ring buffer:
  - Lọc event không cần thiết.
  - Chuyển event thành JSON và enqueue.
- Thread gom event và gửi HTTP POST.

### 2.3 Server Logging
- Nhận POST tại endpoint `/events`.
- Decode JSON array của event.
- Enqueue vào queue server.
- Ghi mỗi event thành 1 dòng JSON trong `events.log`.

## 3. Cấu trúc thư mục
```
demon_ebpf/
├── collector
│   ├── collector.c
│   └── Makefile
├── diagram
│   ├── SAD.mmd
│   ├── seq_collector_init.mmd
│   ├── seq_collector_init_README.md
│   ├── seq_collector_to_server.mmd
│   ├── seq_collector_to_server_README.md
│   ├── seq_server_log.mmd
│   └── seq_server_log_README.md
├── ebpf
│   ├── include
│   │   ├── common.h
│   │   └── vmlinux.h
│   ├── Makefile
│   └── src
│       └── ebpf.c
├── README.md
└── server
    ├── main.go
    └── Makefile
```

 Giải thích:
 - **ebpf/**: code chạy trong kernel.  
 - **collector/**: code user-space để nhận event từ eBPF và gửi server.  
 - **server/**: code server nhận event và ghi log.  
 - **diagram/**: các diagram Mermaid giải thích luồng hoạt động.  
 - **README.md**: giải thích luồng, dùng làm dữ liệu training AI.
