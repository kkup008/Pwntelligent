from pwn import ELF

def print_plt_got(binary_path):
    elf = ELF(binary_path)

    print("\n[*] PLT 表函数及地址:")
    for name, addr in elf.plt.items():
        print(f"  {name:<30} 0x{addr:x}")

    print("\n[*] GOT 表项函数及地址:")
    for name, addr in elf.got.items():
        print(f"  {name:<30} 0x{addr:x}")

    # 主函数地址
    print("\n[*] 主函数 (main) 地址:")
    main_addr = elf.symbols.get('main') or elf.symbols.get('MAIN') or elf.symbols.get('Main')
    if main_addr:
        print(f"  main                           0x{main_addr:x}")
    else:
        print("  [!] 未找到 main 符号（可能被 strip）")

    # bss 段地址
    print("\n[*] .bss 段信息:")
    if elf.bss():
        print(f"  起始地址: 0x{elf.bss():x}")
        # 通常我们不知道 bss 的大小，但可以通过 `.elfstructs` 来补充（或使用 elftools 再扩展）
    else:
        print("  [!] 未找到 .bss 段")
