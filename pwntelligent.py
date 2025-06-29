import argparse
import os
import subprocess
import sys

from core.file_info import get_filename
from core.checksec_info import run_checksec
from core.libc_check import find_libc
from core.patch_binary import patch_binary
from core.seccomp_check import detect_seccomp
from tools.ropper_runner import analyze_gadgets,contains_any_string
from core.plt_got import print_plt_got


def main():
    parser = argparse.ArgumentParser(description="PWN 自动分析器")
    parser.add_argument("binary", help="输入 ELF 二进制路径")
    parser.add_argument("-ld", help="指定 ld 文件，自动执行 patchelf", required=False)
    args = parser.parse_args()

    # 给 libc 和指定 ld 设置执行权限
    if os.path.exists("libc.so.6"):
        subprocess.run(["chmod", "+x", "libc.so.6"], check=True)
    if args.ld and os.path.exists(args.ld):
        subprocess.run(["chmod", "+x", args.ld], check=True)

    original_binary = args.binary
    temp_binary = f"{original_binary}.original"

    if not os.path.exists(temp_binary):
        subprocess.run(["cp", original_binary, temp_binary], check=True)

    filename = get_filename(original_binary)
    print(f"[*] 文件名: {filename}", flush=True)

    # ======================= 阶段 1 =======================
    #print("\n[阶段 1] Checksec 结果 (原始 ELF):")
    #print(run_checksec(temp_binary))

    # ======================= 阶段 2 =======================
    print("\n[阶段 1] 沙箱检测 (seccomp)：", flush=True)
    has_seccomp, blocked = detect_seccomp(temp_binary)
    if has_seccomp is None:
        print("⚠️  检测失败 (可能原因: seccomp-tools 未安装或权限不足)", flush=True)
    elif has_seccomp:
        print("✅ 检测到沙箱规则", flush=True)
        if blocked:
            if blocked == ["<all_non_whitelisted>"]:
                print("   所有非白名单系统调用被限制", flush=True)
            else:
                print("   被限制的系统调用:", flush=True)
                for syscall in blocked:
                    print(f"    - {syscall}", flush=True)
        else:
            print("   (规则存在但无明确系统调用限制)", flush=True)
    else:
        print("❌ 未检测到沙箱规则", flush=True)

    # ======================= 阶段 3 =======================
    print("\n[阶段 2] Gadget 检测：", flush=True)
    gadgets = analyze_gadgets(temp_binary)
    for name in ["pop rdi ; ret", "syscall", "leave ; ret", "jmp rsp", "ret"]:
        addr = gadgets.get(name)
        print(f"    - {name:<14}: {'✅ 地址: ' + addr if addr else '❌ 未找到'}", flush=True)
    print("\n[*] 是否包含潜在 shell 字符串:")
    string_results = contains_any_string(args.binary)
    for s, present in string_results.items():
        print(f"    - {s}: {'✅ 是' if present else '❌ 否'}")


    # ======================= 阶段 4 =======================
    print("\n[阶段 3] 分析并替换 libc.so.6：", flush=True)
    find_libc()
    if os.path.exists("libc.so.6"):
        print("\n是否用当前目录下的 libc.so.6 替换二进制依赖？(y/n)                 : ", end='', flush=True)
        choice = input().strip().lower()
        print(f"你的选择是: {choice}\n")  # 这里加个换行，避免下一次输出挤在同一行
        if choice in ("y", "yes"):
            try:
                abs_binary = os.path.abspath(original_binary)
                abs_libc = os.path.abspath("libc.so.6")

                libc_arch = subprocess.run(["file", abs_libc], stdout=subprocess.PIPE, text=True).stdout
                binary_arch = subprocess.run(["file", abs_binary], stdout=subprocess.PIPE, text=True).stdout

                if "32-bit" in libc_arch and "64-bit" in binary_arch:
                    print("❌ 错误: 32 位 libc 无法用于 64 位二进制", flush=True)
                    sys.exit(1)
                elif "64-bit" in libc_arch and "32-bit" in binary_arch:
                    print("❌ 错误: 64 位 libc 无法用于 32 位二进制", flush=True)
                    sys.exit(1)

                result = subprocess.run(
                    ["patchelf", "--replace-needed", "libc.so.6", abs_libc, abs_binary],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                if result.returncode == 0:
                    print("✅ libc 依赖替换成功！", flush=True)

                    cwd = os.getcwd()
                    rpath_result = subprocess.run(
                        ["patchelf", "--set-rpath", cwd, abs_binary],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                    )

                    if rpath_result.returncode == 0:
                        print(f"✅ 设置 RPATH 为当前目录: {cwd}", flush=True)
                        rpath_check = subprocess.run(
                            ["patchelf", "--print-rpath", abs_binary],
                            stdout=subprocess.PIPE,
                            text=True,
                        )
                        print(f"  当前 RPATH: {rpath_check.stdout.strip()}", flush=True)
                        needed_check = subprocess.run(
                            ["patchelf", "--print-needed", abs_binary],
                            stdout=subprocess.PIPE,
                            text=True,
                        )
                        print(f"  当前依赖: {needed_check.stdout.strip()}", flush=True)
                    else:
                        print("⚠️ 设置 RPATH 失败", flush=True)
                        print(f"   错误信息: {rpath_result.stderr.strip()}", flush=True)
                else:
                    print(f"❌ libc 替换失败: {result.stderr.strip()}", flush=True)
            except Exception as e:
                print(f"❌ 替换 libc 发生异常: {e}", flush=True)
        else:
            print("⏩ 跳过 libc 替换", flush=True)

    # ======================= 阶段 5 =======================
    if args.ld:
        print("\n[阶段 4] 设置自定义动态链接器（ld）:", flush=True)
        patch_binary(original_binary, args.ld)

    # 清理临时副本
    if os.path.exists(temp_binary):
        os.remove(temp_binary)

    # ======================= 最终结果 =======================
    print("\n[最终结果] 替换后 Checksec:", flush=True)
    print_plt_got(original_binary)


if __name__ == "__main__":
    main()

