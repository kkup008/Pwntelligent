import subprocess
import re

def analyze_gadgets(binary_path):
    def find_gadget(output, keyword):
        for line in output.splitlines():
            if keyword in line:
                match = re.search(r"(0x[0-9a-fA-F]+)", line)
                if match:
                    return match.group(1)
        return None

    def find_one_ret(output):
        for line in output.splitlines():
            if re.match(r"0x[0-9a-fA-F]+ : ret", line.strip()):
                return line.split(':')[0].strip()
        return None

    try:
        gadgets = {}

        # pop rdi ; ret
        out = subprocess.check_output(
            ["ROPgadget", "--binary", binary_path, "--only", "pop|ret"],
            stderr=subprocess.DEVNULL
        ).decode()
        gadgets["pop rdi ; ret"] = find_gadget(out, "pop rdi")

        # syscall
        out = subprocess.check_output(
            ["ROPgadget", "--binary", binary_path, "--only", "syscall"],
            stderr=subprocess.DEVNULL
        ).decode()
        gadgets["syscall"] = find_gadget(out, "syscall")

        # leave ; ret
        out = subprocess.check_output(
            ["ROPgadget", "--binary", binary_path, "--only", "leave"],
            stderr=subprocess.DEVNULL
        ).decode()
        gadgets["leave ; ret"] = find_gadget(out, "leave ; ret")

        # jmp rsp
        out = subprocess.check_output(
            ["ROPgadget", "--binary", binary_path, "--only", "jmp"],
            stderr=subprocess.DEVNULL
        ).decode()
        gadgets["jmp rsp"] = find_gadget(out, "jmp rsp")

        # ret (for stack alignment)
        out = subprocess.check_output(
            ["ROPgadget", "--binary", binary_path, "--only", "ret"],
            stderr=subprocess.DEVNULL
        ).decode()
        gadgets["ret"] = find_one_ret(out)

        return gadgets

    except Exception as e:
        print(f"[!] ROPgadget 分析失败: {e}")
        return {}

def contains_any_string(binary_path, target_strings=None):
    """
    查找指定的目标字符串是否存在于二进制中。
    默认查找常见用于 shell 的字符串，如 /bin/sh, /sh, $0。
    """
    if target_strings is None:
        target_strings = ["/bin/sh", "/sh", "$0"]
    
    try:
        output = subprocess.check_output(["strings", binary_path])
        return {s: s.encode() in output for s in target_strings}
    except Exception as e:
        print(f"[!] 字符串检测失败: {e}")
        return {s: False for s in target_strings}
