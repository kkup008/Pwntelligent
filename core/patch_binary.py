import os
import subprocess

def patch_binary(binary_path, ld_path):
    if not os.path.exists("libc.so.6"):
        print("❌ 无法执行 patchelf，libc.so.6 未找到")
        return

    if not os.path.exists(ld_path):
        print(f"❌ 指定的 ld 文件 {ld_path} 不存在")
        return

    print(f"[*] 使用 patchelf 修改 {binary_path}")
    try:
        subprocess.run(["patchelf", "--set-interpreter", ld_path, binary_path], check=True)
        subprocess.run(["patchelf", "--set-rpath", ".", binary_path], check=True)
        print("✅ ld 替换成功！")
    except subprocess.CalledProcessError as e:
        print(f"❌ patchelf 修改失败: {e}")
