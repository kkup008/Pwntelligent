import os
import subprocess

def find_libc():
    if os.path.exists("libc.so.6"):
        print("[*] 检测到当前目录下存在 libc.so.6")
        try:
            result = subprocess.check_output("strings libc.so.6 | grep ubuntu", shell=True)
            print("[*] libc.so.6 版本信息（ubuntu相关）：")
            print(result.decode())
        except subprocess.CalledProcessError:
            print("⚠️  未找到与 ubuntu 相关的版本信息")
    else:
        print("❌ 当前目录下未找到 libc.so.6 文件")