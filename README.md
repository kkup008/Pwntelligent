# 🔍 Pwntelligent --kkup008

原创:一个专为 CTF 二进制题目设计的自动分析工具，支持对 ELF 文件进行快速环境补丁、沙箱检测、ROP Gadget 扫描、libc 替换、PLT/GOT 提取等操作。支持 32 位 / 64 位 ELF，可辅助快速定位可利用点。

---

##  功能特性

-  一键自动分析 ELF 可执行文件
-  支持 seccomp 沙箱检测（基于 `seccomp-tools`）
-  提取关键 ROP Gadget（基于 `ROPgadget`）
-  定位各种shell的操作
-  自动识别并替换 `libc.so.6` 依赖，可设置 RPATH
-  支持指定 `ld` 动态链接器文件，自动注入
-  提取 GOT / PLT 表、主函数地址、.bss 段等
-  AI增加了些图形化,美观
-  输出高亮美观（基于 `colorama`）

---

##  安装依赖(pwn手可以直接跳过)

建议使用 Ubuntu 环境。
```bash
sudo apt update
sudo apt install python3.12-venv
```
创建一个虚拟的python的环境使用,环境隔离一下
```bash
python3 -m venv venv
source venv/bin/activate
```
启动环境
```bash
pip install -r requirements.txt
```
先安装下来
```c
pwntools
ROPgadget
```
过程可能比较慢,因为pwn的环境非常难搭建,此外一些工具需要很强的环境依赖性,不过pwn手这些工具应该都有,那么下一步:我们接着安装检测沙箱的依赖
```bash
sudo apt install gcc ruby-dev
sudo gem install seccomp-tools
```
接着安装checksec
```bash
git clone https://github.com/slimm609/checksec.sh
sudo cp checksec /usr/local/bin/
```
安装elftools
```bash
sudo apt update
sudo apt install patchelf
```



## 使用须知  
python3 pwntelligent.py [-ld]可以加参数
```bash
python3 pwntelligent.py -ld ld-2.23.so test
```
效果如下
```bash
[*] 文件名: test

[阶段 1] 沙箱检测 (seccomp)：
✅ 检测到沙箱规则
   被限制的系统调用:
    - exit
    - exit_group
    - open
    - read
    - rt_sigreturn
    - sigreturn
    - write

[阶段 2] Gadget 检测：
    - pop rdi ; ret : ❌ 未找到
    - syscall       : ❌ 未找到
    - leave ; ret   : ❌ 未找到
    - jmp rsp       : ❌ 未找到
    - ret           : ✅ 地址: 0x0804833a

[*] 是否包含潜在 shell 字符串:
    - /bin/sh: ❌ 否
    - /sh: ❌ 否
    - $0: ❌ 否

[阶段 3] 分析并替换 libc.so.6：
[*] 检测到当前目录下存在 libc.so.6
[*] libc.so.6 版本信息（ubuntu相关）：
GNU C Library (Ubuntu GLIBC 2.23-0ubuntu11.3) stable release version 2.23, by Roland McGrath et al.
<https://bugs.launchpad.net/ubuntu/+source/glibc/+bugs>.


是否用当前目录下的 libc.so.6 替换二进制依赖？(y/n)  y
你的选择是: y

✅ libc 依赖替换成功！
✅ 设置 RPATH 为当前目录: /home/ubuntu/Desktop/Pwntelligent
  当前 RPATH: /home/ubuntu/Desktop/Pwntelligent
  当前依赖: /home/ubuntu/Desktop/Pwntelligent/libc.so.6

[阶段 4] 设置自定义动态链接器（ld）:
[*] 使用 patchelf 修改 test
✅ ld 替换成功！

[最终结果] 替换后 Checksec:
[*] '/home/ubuntu/Desktop/Pwntelligent/test'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX unknown - GNU_STACK missing
    PIE:      No PIE (0x8030000)
    Stack:    Executable
    RWX:      Has RWX segments
    RUNPATH:  b'.'

[*] PLT 表函数及地址:
  read                           0x8048370
  printf                         0x8048380
  __stack_chk_fail               0x8048390
  __libc_start_main              0x80483a0
  prctl                          0x80483b0
  __gmon_start__                 0x80483c0

[*] GOT 表项函数及地址:
  __gmon_start__                 0x8049ffc
  read                           0x804a00c
  printf                         0x804a010
  __stack_chk_fail               0x804a014
  __libc_start_main              0x804a018
  prctl                          0x804a01c

[*] 主函数 (main) 地址:
  main                           0x8048548

[*] .bss 段信息:
  起始地址: 0x804a040
```
增加了对系统got表和plt表的直接调用输出,增加了各种shell定位,通过AI增加了一些图形化,美观度整体不错,此外后续会增加自动构造常用poc盲打等手段
