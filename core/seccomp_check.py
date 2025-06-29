import subprocess
import re
import os
from typing import Tuple, List, Optional

def detect_seccomp(binary_path: str) -> Tuple[bool, Optional[List[str]]]:
    """
    调用 seccomp-tools dump 并解析输出，检测二进制是否存在 seccomp 规则
    """
    try:
        # 确保使用绝对路径
        abs_path = os.path.abspath(binary_path)
        if not os.path.exists(abs_path):
            return False, None

        # 执行 seccomp-tools dump
        proc = subprocess.run(
            ['seccomp-tools', 'dump', abs_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=5
        )
        
        output = proc.stdout or ''
        
        # 如果没有任何输出，视为无 seccomp 规则
        if not output.strip():
            return False, None

        # 检测是否有任何过滤规则
        has_any_rule = False
        blocked_syscalls = []
        
        # 逐行解析输出
        for line in output.splitlines():
            # 忽略空行和标题行
            if not line.strip() or line.startswith(" line ") or line.startswith("======"):
                continue
                
            # 检查是否包含过滤规则（if 语句）
            if "if (" in line:
                has_any_rule = True
                
                # 尝试提取系统调用名称
                match = re.search(r"if \(A ==\s*([\w_]+)", line)
                if match:
                    syscall = match.group(1)
                    if syscall not in ('ARCH_I386', 'ARCH_X86_64', 'arch'):
                        blocked_syscalls.append(syscall)
            
            # 检查是否包含拦截规则（return ERRNO/KILL）
            if "return" in line and ("ERRNO" in line or "KILL" in line):
                has_any_rule = True
                
                # 如果没有提取到具体系统调用，则标记为通用拦截
                if not blocked_syscalls:
                    return True, ['<all_non_whitelisted>']
        
        # 逻辑判断
        if blocked_syscalls:
            return True, sorted(set(blocked_syscalls))
        elif has_any_rule:
            return True, None
        else:
            return False, None

    except FileNotFoundError:
        return None, None
    except subprocess.TimeoutExpired:
        return None, None
    except Exception:
        return None, None