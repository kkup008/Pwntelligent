import subprocess

def run_checksec(binary_path):
    try:
        output = subprocess.check_output(["checksec", "--file", binary_path])
        return output.decode()
    except Exception as e:
        return f"[!] checksec 失败: {e}"