import sys
import subprocess
import ipaddress
import os

def check_rst_signature(src_ip_str, dst_ip_str, ttl_str, win_size_str, ip_id_str):
    """
    根据提供的C代码逻辑，检查RST包的签名。
    """
    try:
        # 1. 将所有输入字符串转换为整数
        # ipaddress.IPv4Address() 将 "1.2.3.4" 转换为整数，等效于 C 中的 s_addr
        src_ip_raw = int(ipaddress.IPv4Address(src_ip_str))
        dst_ip_raw = int(ipaddress.IPv4Address(dst_ip_str))
        # 反转大端/小端（4 字节）
        src_ip = int.from_bytes(src_ip_raw.to_bytes(4, 'big'), 'little')
        dst_ip = int.from_bytes(dst_ip_raw.to_bytes(4, 'big'), 'little')

        ttl = int(ttl_str)
        win_size = int(win_size_str)
        ip_id = int(ip_id_str,0) # tshark -e ip.id 默认输出十进制
    except Exception as e:
        # print(f"Skipping packet (data conversion error): {e}", file=sys.stderr)
        return False

    # C 代码中的 "if (ntohs(tcp_hdr->th_win))" 检查窗口大小是否为0
    if win_size == 0:
        return False

    signature_seed1 = 65535
    signature_seed2 = 13

    # --- 情形 A：按 (src -> dst) 推导 ---
    # C: val2 = (signature_seed1 + ip_hdr->ip_src.s_addr % ntohs(tcp_hdr->th_win) - ntohs(ip_hdr->ip_id));
    # C: val3 = ntohs(tcp_hdr->th_win) - ip_hdr->ip_dst.s_addr % signature_seed2;
    val2_a = (signature_seed1 + src_ip % win_size - ip_id) / signature_seed2
    val3_a = (win_size - dst_ip % signature_seed2)

    if val2_a == val3_a:
        # C: if ((u_char)(val2 % 200 + 48) >= ip_hdr->ip_ttl)
        if (val2_a % 200 + 48) >= ttl:
            return True

    # --- 情形 B：按 (dst -> src) 对调再算一次 ---
    # C: val2 = (signature_seed1 + ip_hdr->ip_dst.s_addr % ntohs(tcp_hdr->th_win) - ntohs(ip_hdr->ip_id));
    # C: val3 = ntohs(tcp_hdr->th_win) - ip_hdr->ip_src.s_addr % signature_seed2;
    val2_b = (signature_seed1 + dst_ip % win_size - ip_id) / signature_seed2
    val3_b = (win_size - src_ip % signature_seed2)

    if val2_b == val3_b:
        # C: if ((u_char)(val2 % 200 + 48) >= ip_hdr->ip_ttl)
        if (val2_b % 200 + 48) >= ttl:
            return True

    # 两种情形都不匹配
    return False

def main():
    # --- 1. 检查输入参数 ---
    if len(sys.argv) < 2:
        print(f"用法: python {sys.argv[0]} <pcap/pcapng 文件路径> [输出模式] [输出文件路径] [tshark.exe 路径]")
        print(f"输出模式: 0=控制台显示(默认) 1=只输出命中的RST到文件 2=输出所有RST到文件")
        print(f'示例: python analyze_rst.py "D:\\captures\\my_traffic.pcapng"')
        print(f'      python analyze_rst.py "D:\\captures\\my_traffic.pcapng" 1 "hits.txt"')
        print(f'      python analyze_rst.py "D:\\captures\\my_traffic.pcapng" 2 "all_rst.txt"')
        print(f'      python analyze_rst.py "D:\\captures\\my_traffic.pcapng" 0 "" "C:\\Program Files\\Wireshark\\tshark.exe"')
        sys.exit(1)

    # 解析参数
    pcap_path = sys.argv[1]
    
    # 默认值
    output_mode = 0  # 0=控制台显示, 1=只输出命中的到文件, 2=输出所有到文件
    output_file = "results.txt"
    tshark_path = ""
    
    # 解析可选参数
    if len(sys.argv) >= 3:
        try:
            output_mode = int(sys.argv[2])
            if output_mode not in [0, 1, 2]:
                print(f"错误: 输出模式必须是 0, 1 或 2")
                sys.exit(1)
        except ValueError:
            print(f"错误: 输出模式必须是数字")
            sys.exit(1)
    
    if len(sys.argv) >= 4:
        output_file = sys.argv[3]
    
    if len(sys.argv) >= 5:
        tshark_path = sys.argv[4]
    
    # 如果没有指定 tshark 路径,使用默认路径
    if not tshark_path:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        # 根据操作系统选择合适的 tshark 路径
        if sys.platform == "win32":
            tshark_path = os.path.join(script_dir, "tshark", "tshark.exe")
        else:
            # Linux/macOS: 优先使用脚本目录下的 tshark,否则使用系统 tshark
            local_tshark = os.path.join(script_dir, "tshark", "tshark")
            if os.path.exists(local_tshark):
                tshark_path = local_tshark
            else:
                tshark_path = "tshark"  # 使用系统 PATH 中的 tshark
    
    # 检查输出模式是否需要文件路径
    if output_mode in [1, 2] and not output_file:
        print(f"错误: 输出模式 {output_mode} 需要指定输出文件路径")
        sys.exit(1)

    # 检查 tshark 和 pcap 文件是否存在
    # 如果 tshark_path 只是 "tshark"(系统命令),则跳过文件存在性检查
    if tshark_path != "tshark" and not os.path.exists(tshark_path):
        print(f"错误: tshark 未找到: {tshark_path}")
        print(f"提示: 在 Linux 上,请通过 'sudo apt install tshark' 或 'sudo yum install wireshark' 安装")
        sys.exit(1)
    if not os.path.exists(pcap_path):
        print(f"错误: pcap 文件未找到: {pcap_path}")
        sys.exit(1)

    # --- 2. 构建 tshark 命令 ---
    # -r: 读取文件
    # -Y: 显示过滤器，只看 TCP RST 包
    # -T fields: 以字段形式输出
    # -e ...: 指定要提取的字段
    # -E header=n: 不打印表头
    # -E separator=,: 使用逗号作为分隔符
    tshark_cmd = [
        tshark_path,
        "-r", pcap_path,
        "-Y", "tcp.flags.reset == 1",
        "-T", "fields",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "ip.ttl",
        "-e", "tcp.window_size",
        "-e", "ip.id",
        "-E", "header=n",
        "-E", "separator=,"
    ]

    print(f"正在使用 tshark 分析文件: {pcap_path}...")
    
    # 准备输出
    output_file_handle = None
    if output_mode in [1, 2]:
        try:
            output_file_handle = open(output_file, 'w', encoding='utf-8')
            print(f"输出将写入文件: {output_file}")
        except Exception as e:
            print(f"错误: 无法创建输出文件 {output_file}: {e}")
            sys.exit(1)
    
    # 输出表头
    header_line = f"{'源 IP':<18} {'目的 IP':<18} {'是否命中'}"
    separator_line = f"{'='*18:<18} {'='*18:<18} {'='*8}"
    
    if output_mode == 0:  # 控制台显示
        print("---" * 10)
        print(header_line)
        print(separator_line)
    else:  # 文件输出
        output_file_handle.write(header_line + "\n")
        output_file_handle.write(separator_line + "\n")

    try:
        # --- 3. 执行 tshark 命令并捕获输出 ---
        process = subprocess.run(
            tshark_cmd,
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='ignore', # 忽略 tshark 可能的 utf-8 编码错误
            check=True # 如果 tshark 失败则抛出异常
        )

        # --- 4. 逐行处理 tshark 输出 ---
        hit_count = 0
        total_rst_count = 0
        
        for line in process.stdout.strip().splitlines():
            parts = line.split(',')
            if len(parts) == 5:
                src_ip, dst_ip, ttl, win_size, ip_id = parts
                
                # 检查是否有空字段 (tshark 可能对某些包无法解析全部字段)
                if not all([src_ip, dst_ip, ttl, win_size, ip_id]):
                    continue
                
                total_rst_count += 1
                    
                # 执行签名检查
                is_hit = check_rst_signature(src_ip, dst_ip, ttl, win_size, ip_id)
                hit_str = "是" if is_hit else "否"
                
                if is_hit:
                    hit_count += 1
                
                # 根据输出模式决定是否输出
                should_output = False
                if output_mode == 0:  # 控制台显示所有
                    should_output = True
                elif output_mode == 1:  # 只输出命中的到文件
                    should_output = is_hit
                elif output_mode == 2:  # 输出所有RST到文件
                    should_output = True
                
                if should_output:
                    output_line = f"{src_ip:<18} {dst_ip:<18} {ip_id:<8} {win_size:<8} {ttl:<6} {hit_str}"
                    if output_mode == 0:
                        print(output_line)
                    else:
                        output_file_handle.write(output_line + "\n")

    except subprocess.CalledProcessError as e:
        print(f"tshark 执行出错:", file=sys.stderr)
        print(e.stderr, file=sys.stderr)
    except Exception as e:
        print(f"脚本执行时发生未知错误: {e}", file=sys.stderr)
    finally:
        # 关闭输出文件
        if output_file_handle:
            output_file_handle.close()

    # 输出统计信息
    if output_mode == 0:
        print("---" * 10)
    
    summary_msg = f"分析完成。共找到 {total_rst_count} 个RST包，其中 {hit_count} 个命中签名。"
    
    if output_mode == 0:
        print(summary_msg)
    else:
        print(summary_msg)
        print(f"结果已保存到: {output_file}")

if __name__ == "__main__":
    main()