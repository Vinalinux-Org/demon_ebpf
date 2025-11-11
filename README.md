# eBPF Event Monitor

## 1. Bối cảnh

Trong hệ thống Linux, việc theo dõi các sự kiện của tiến trình user-space là rất quan trọng cho mục đích monitor, audit hoặc EDR.  

Mục tiêu của dự án là xây dựng một hệ thống monitor realtime, có khả năng thu thập, truyền và lưu trữ các sự kiện, để phục vụ cho việc phân tích hoặc giám sát hệ thống.

---

## 2. Requirement

Hệ thống cần đáp ứng các yêu cầu chính:

- Quan sát sự kiện: thu thập thông tin cơ bản của event (PID, UID, cgroup, timestamp,…).  
- Tách biệt các layer:
  - Kernel (eBPF) chỉ thu thập event, không xử lý logic.  
  - User-space collector nhận event và gửi server.  
  - Server nhận event và ghi log.

---

## 3. Solution

Hệ thống được thiết kế theo **3 thành phần chính**:

### 3.1 eBPF Kernel Module
- Hook các điểm trong kernel để quan sát event.  
- Lưu thông tin event vào struct chung.  
- Push event lên user-space thông qua **Ring Buffer** (libbpf).

### 3.2 User-space Collector
- Nhận event từ ring buffer bằng callback libbpf.  
- Lọc bỏ các event không cần thiết.  
- Chuyển event thành JSON, enqueue vào queue nội bộ.  
- Gửi event tới server.  

### 3.3 Server
- Nhận HTTP POST JSON từ collector.  
- Parse và enqueue event vào queue.  
- Ghi mỗi event thành một dòng JSON trong file log.  
