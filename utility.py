import subprocess
import os
import yaml
import re
import matplotlib.pyplot as plt
import socket
import numpy as np
import pandas as pd
import seaborn as sns
import sys
import time
import psutil
import time
from typing import Dict, Any, Tuple

OPENSSL_PATH = "/usr/local/ssl/bin/openssl"
#os.environ['OPENSSL_MODULES'] = '/Users/greedyshark/Documents/GitHub/oqs-provider_new/_build/lib'

pqc_algorithms = ['falcon512', 'falcon1024', 'falconpadded512', 'falconpadded1024',
                      'dilithium2', 'dilithium3', 'dilithium5',
                      'sphincssha2128fsimple', 'sphincssha2128ssimple', 'sphincssha2192fsimple',
                      'sphincsshake128fsimple',
                      'mldsa44', 'mldsa65', 'mldsa87',
                      'mayo1', 'mayo2', 'mayo3', 'mayo5']
hybrid_algorithms = ['p256_falcon512', 'rsa3072_falcon512', 'p521_falcon1024',
                         'p256_sphincssha2128fsimple', 'rsa3072_sphincssha2128fsimple',
                         'p256_dilithium2', 'rsa3072_dilithium2', 'p384_dilithium3', 'p521_dilithium5',
                         'p256_mldsa44', 'rsa3072_mldsa44', 'p384_mldsa65', 'p521_mldsa87']








def run_tc_command(command):
    print(f"Running command: {' '.join(command)}")
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode != 0:
        print(f"Command failed: {' '.join(command)}")
        print(f"Stdout: {result.stdout}")
        print(f"Stderr: {result.stderr}")
        raise subprocess.CalledProcessError(result.returncode, command, output=result.stdout, stderr=result.stderr)
    else:
        print(f"Command succeeded: {' '.join(command)}")

def delete_network_namespaces():
    """
    删除现有的 server_ns 和 client_ns 命名空间。
    """
    namespaces = ['server_ns', 'client_ns']
    for ns in namespaces:
        try:
            subprocess.run(['sudo', 'ip', 'netns', 'delete', ns], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            print(f"Deleted existing network namespace: {ns}")
        except subprocess.CalledProcessError:
            print(f"Network namespace {ns} does not exist or failed to delete. Continuing...")

def create_network_namespaces():
    """
    创建新的 server_ns 和 client_ns 命名空间，并配置 veth 对。
    """
    try:
        # 创建命名空间
        subprocess.run(['sudo', 'ip', 'netns', 'add', 'server_ns'], check=True)
        subprocess.run(['sudo', 'ip', 'netns', 'add', 'client_ns'], check=True)
        print("Created network namespaces: server_ns, client_ns")

        # 创建 veth 对
        subprocess.run(['sudo', 'ip', 'link', 'add', 'veth0', 'type', 'veth', 'peer', 'name', 'veth1'], check=True)
        print("Created veth pair: veth0 <-> veth1")

        # 将 veth0 移动到 server_ns，veth1 移动到 client_ns
        subprocess.run(['sudo', 'ip', 'link', 'set', 'veth0', 'netns', 'server_ns'], check=True)
        subprocess.run(['sudo', 'ip', 'link', 'set', 'veth1', 'netns', 'client_ns'], check=True)
        print("Assigned veth0 to server_ns and veth1 to client_ns")

        # 列出 server_ns 中的接口
        print("Interfaces in server_ns before setting up:")
        subprocess.run(['sudo', 'ip', 'netns', 'exec', 'server_ns', 'ip', 'link', 'show'], check=True)

        # 配置 IP 地址和启动接口
        # 在 server_ns 中
        subprocess.run(['sudo', 'ip', 'netns', 'exec', 'server_ns', 'ip', 'addr', 'add', '10.200.1.1/24', 'dev', 'veth0'], check=True)
        subprocess.run(['sudo', 'ip', 'netns', 'exec', 'server_ns', 'ip', 'link', 'set', 'veth0', 'up'], check=True)
        subprocess.run(['sudo', 'ip', 'netns', 'exec', 'server_ns', 'ip', 'link', 'set', 'lo', 'up'], check=True)  # 确保使用 'lo'

        # 列出 server_ns 中的接口
        print("Interfaces in server_ns after setting up:")
        subprocess.run(['sudo', 'ip', 'netns', 'exec', 'server_ns', 'ip', 'link', 'show'], check=True)

        # 在 client_ns 中
        subprocess.run(['sudo', 'ip', 'netns', 'exec', 'client_ns', 'ip', 'addr', 'add', '10.200.1.2/24', 'dev', 'veth1'], check=True)
        subprocess.run(['sudo', 'ip', 'netns', 'exec', 'client_ns', 'ip', 'link', 'set', 'veth1', 'up'], check=True)
        subprocess.run(['sudo', 'ip', 'netns', 'exec', 'client_ns', 'ip', 'link', 'set', 'lo', 'up'], check=True)  # 确保使用 'lo'

        # 列出 client_ns 中的接口
        print("Interfaces in client_ns after setting up:")
        subprocess.run(['sudo', 'ip', 'netns', 'exec', 'client_ns', 'ip', 'link', 'show'], check=True)

        print("Configured IP addresses and brought up interfaces in both namespaces.")

    except subprocess.CalledProcessError as e:
        error_message = e.stderr.decode() if e.stderr else 'No error message'
        print(f"Failed to create and configure network namespaces: {error_message}", file=sys.stderr)
        sys.exit(1)

def set_network_conditions(packet_loss=None, bandwidth=None, interface='veth0'):
    """
    设置网络条件，例如丢包率和带宽限制。
    """
    try:
        # 删除现有的 qdisc（忽略错误）
        cmd_del_veth0 = ["sudo", "ip", "netns", "exec", "server_ns", "tc", "qdisc", "del", "dev", interface, "root"]
        subprocess.run(cmd_del_veth0, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    
        if bandwidth:
            # 添加 htb 根 qdisc 到 veth0，明确指定 handle 1:
            cmd_add_htb = [
                "sudo", "ip", "netns", "exec", "server_ns",
                "tc", "qdisc", "add", "dev", interface, "root", "handle", "1:", "htb", "default", "12"
            ]
            subprocess.run(cmd_add_htb, check=True)
    
            # 添加 htb 类
            cmd_add_class = [
                "sudo", "ip", "netns", "exec", "server_ns",
                "tc", "class", "add", "dev", interface, "parent", "1:", "classid", "1:12", "htb", "rate", bandwidth
            ]
            subprocess.run(cmd_add_class, check=True)
    
            # 添加 netem qdisc 到 htb 类
            cmd_add_netem = ["sudo", "ip", "netns", "exec", "server_ns", "tc", "qdisc", "add", "dev", interface, "parent", "1:12", "handle", "10:", "netem"]
            if packet_loss is not None:
                cmd_add_netem.extend(["loss", f"{packet_loss}%"])
            subprocess.run(cmd_add_netem, check=True)
        else:
            # 仅添加 netem qdisc 到 root
            cmd_add_netem = ["sudo", "ip", "netns", "exec", "server_ns", "tc", "qdisc", "add", "dev", interface, "root", "handle", "1:", "netem"]
            if packet_loss is not None:
                cmd_add_netem.extend(["loss", f"{packet_loss}%"])
            subprocess.run(cmd_add_netem, check=True)
    
        print(f"Network conditions set on server_ns: packet_loss={packet_loss}%, bandwidth={bandwidth} on {interface}")
    
        # 设置 veth1 在 client_ns 中
        interface_client = 'veth1'
        subprocess.run(["sudo", "ip", "netns", "exec", "client_ns", "tc", "qdisc", "del", "dev", interface_client, "root"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    
        if bandwidth:
            # 添加 htb 根 qdisc 到 veth1，明确指定 handle 1:
            cmd_add_htb_client = [
                "sudo", "ip", "netns", "exec", "client_ns",
                "tc", "qdisc", "add", "dev", interface_client, "root", "handle", "1:", "htb", "default", "12"
            ]
            subprocess.run(cmd_add_htb_client, check=True)
    
            # 添加 htb 类
            cmd_add_class_client = [
                "sudo", "ip", "netns", "exec", "client_ns",
                "tc", "class", "add", "dev", interface_client, "parent", "1:", "classid", "1:12", "htb", "rate", bandwidth
            ]
            subprocess.run(cmd_add_class_client, check=True)
    
            # 添加 netem qdisc 到 htb 类
            cmd_add_netem_client = ["sudo", "ip", "netns", "exec", "client_ns", "tc", "qdisc", "add", "dev", interface_client, "parent", "1:12", "handle", "10:", "netem"]
            if packet_loss is not None:
                cmd_add_netem_client.extend(["loss", f"{packet_loss}%"])
            subprocess.run(cmd_add_netem_client, check=True)
        else:
            # 仅添加 netem qdisc 到 root
            cmd_add_netem_client = ["sudo", "ip", "netns", "exec", "client_ns", "tc", "qdisc", "add", "dev", interface_client, "root", "handle", "1:", "netem"]
            if packet_loss is not None:
                cmd_add_netem_client.extend(["loss", f"{packet_loss}%"])
            subprocess.run(cmd_add_netem_client, check=True)
    
        print(f"Network conditions set on client_ns: packet_loss={packet_loss}%, bandwidth={bandwidth} on {interface_client}")
    
    except subprocess.CalledProcessError as e:
        stderr = e.stderr.decode() if e.stderr else 'No error message'
        print(f"Failed to set network conditions: {stderr}", file=sys.stderr)
        sys.exit(1)

def setup_network_namespaces():
    """
    清理现有网络命名空间并创建新的命名空间和网络配置。
    """
    delete_network_namespaces()
    create_network_namespaces()
    # 等待网络接口完全启动
    time.sleep(2)


def find_free_ports(num_ports):
    ports = []
    for _ in range(num_ports):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('', 0))
            ports.append(s.getsockname()[1])
    return ports




def run_command(command):
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Command failed: {' '.join(command)}")
        print(f"Error output: {e.stderr}")
        return None


# 添加一个调试函数来打印环境信息
def print_debug_info():
    print("Python version:", sys.version)
    print("Operating System:", os.name, "-", sys.platform)
    print("OpenSSL version:")
    subprocess.run(["openssl", "version", "-a"], check=False)
    print("Environment variables:")
    for key, value in os.environ.items():
        print(f"{key}={value}")


def generate_cert_and_key(key_dir, sig_algorithm):
    cert_file = os.path.join(key_dir, "cert.pem")
    key_file = os.path.join(key_dir, "key.pem")

    # 定义算法分类
    pqc_algorithms = ['falcon512', 'falcon1024', 'falconpadded512', 'falconpadded1024',
                      'dilithium2', 'dilithium3', 'dilithium5',
                      'sphincssha2128fsimple', 'sphincssha2128ssimple', 'sphincssha2192fsimple',
                      'sphincsshake128fsimple',
                      'mldsa44', 'mldsa65', 'mldsa87',
                      'mayo1', 'mayo2', 'mayo3', 'mayo5']
    hybrid_algorithms = ['p256_falcon512', 'rsa3072_falcon512', 'p521_falcon1024',
                         'p256_sphincssha2128fsimple', 'rsa3072_sphincssha2128fsimple',
                         'p256_dilithium2', 'rsa3072_dilithium2', 'p384_dilithium3', 'p521_dilithium5',
                         'p256_mldsa44', 'rsa3072_mldsa44', 'p384_mldsa65', 'p521_mldsa87']

    # 标准化算法名称
    sig_algorithm = sig_algorithm.lower()

    # 确定算法类型和相应的命令
    if sig_algorithm in pqc_algorithms or sig_algorithm in hybrid_algorithms:
        key_gen_command = [
            OPENSSL_PATH, "genpkey",
            "-algorithm", sig_algorithm,
            "-out", key_file,
            "-provider", "oqsprovider",
            "-provider", "default"
        ]
        
        cert_gen_command = [
            OPENSSL_PATH, "req", "-new",
            "-key", key_file,
            "-x509", "-days", "365",
            "-out", cert_file,
            "-subj", "/CN=localhost",
            "-provider", "oqsprovider",
            "-provider", "default"
        ]
        
        print(f"Generating key with command: {' '.join(key_gen_command)}")
        subprocess.run(key_gen_command, check=True)
        
        print(f"Generating certificate with command: {' '.join(cert_gen_command)}")
        subprocess.run(cert_gen_command, check=True)
    
    
    elif sig_algorithm.startswith('rsa:'):
        key_size = sig_algorithm.split(':')[1]
        command = [
            "openssl", "req", "-x509", "-new", 
            "-newkey", f"rsa:{key_size}",
            "-keyout", key_file, "-out", cert_file,
            "-days", "365", "-nodes", "-subj", "/CN=localhost"
        ]
        print(f"Generating certificate and key with command: {' '.join(command)}")
        subprocess.run(command, check=True)
    
    else:
        # 对于其他未知类型，尝试直接使用算法名称
        command = [
            "openssl", "req", "-x509", "-new", "-newkey", sig_algorithm,
            "-keyout", key_file, "-out", cert_file,
            "-days", "365", "-nodes", "-subj", "/CN=localhost"
        ]
        print(f"Generating certificate and key with command: {' '.join(command)}")
        subprocess.run(command, check=True)

    print("Certificate and key generated successfully")

def ping_server():
    try:
        subprocess.run(
            ["sudo", "ip", "netns", "exec", "client_ns", "ping", "-c", "4", "10.200.1.1"],
            check=True
        )
        print("Ping to server_ns (10.200.1.1) successful.")
    except subprocess.CalledProcessError as e:
        print("Ping to server_ns failed. Check network configuration.")
        sys.exit(1)

def load_config(config_file):
    with open(config_file, 'r') as file:
        config = yaml.safe_load(file)
    kem = config['algorithms']['kem']
    sig = config['algorithms']['sig']
    network = config.get('network_settings', {})
    
    # 验证packet_loss
    packet_loss = network.get('packet_loss')
    if packet_loss is not None:
        if not isinstance(packet_loss, (int, float)) or not (0 <= packet_loss <= 100):
            raise ValueError("packet_loss must be a number between 0 and 100")
    
    # 验证bandwidth
    bandwidth = network.get('bandwidth')
    if bandwidth is not None:
        if not isinstance(bandwidth, str) or not re.match(r'^\d+(kbit|mbit|gbit)$', bandwidth):
            raise ValueError("bandwidth must be a string with units, e.g., '100mbit'")
    
    # 验证接口在相应的命名空间中是否存在
    interface = network.get('interface', 'veth0')
    interface_client = 'veth1'
    
    # 检查 server_ns 中的 veth0
    try:
        interfaces_server = subprocess.check_output(['sudo', 'ip', 'netns', 'exec', 'server_ns', 'ip', 'link', 'show'], text=True)
        if interface not in interfaces_server:
            raise ValueError(f"Network interface '{interface}' does not exist in 'server_ns'.")
    except subprocess.CalledProcessError as e:
        raise ValueError(f"Failed to list interfaces in 'server_ns': {e.stderr}")
    
    # 检查 client_ns 中的 veth1
    try:
        interfaces_client = subprocess.check_output(['sudo', 'ip', 'netns', 'exec', 'client_ns', 'ip', 'link', 'show'], text=True)
        if interface_client not in interfaces_client:
            raise ValueError(f"Network interface '{interface_client}' does not exist in 'client_ns'.")
    except subprocess.CalledProcessError as e:
        raise ValueError(f"Failed to list interfaces in 'client_ns': {e.stderr}")
    
    return kem, sig, network

def save_result(result_dir, algorithm, results, client_output):
    """
    保存基准测试结果到文件
    
    Args:
        result_dir: 结果保存目录
        algorithm: 算法名称
        results: 包含多次运行结果的列表，每个元素是包含详细信息的字典
        client_output: 客户端输出信息
    """
    # 从结果中提取各项指标
    total_runs = len(results)
    successful_runs = len([r for r in results if r['success']])
    failed_runs = total_runs - successful_runs
    error_rate = (failed_runs / total_runs * 100) if total_runs > 0 else 0
    success_rate = 100 - error_rate
    
    # 提取成功运行的性能数据
    handshake_times = [r['handshake_time'] for r in results if r['success'] and r['handshake_time'] is not None]
    memory_usages = [r['memory_usage'] for r in results if r['success'] and r['memory_usage'] is not None]
    cpu_usages = [r['cpu_usage'] for r in results if r['success'] and r['cpu_usage'] is not None]
    cpu_usages_total = [r['cpu_usage_total'] for r in results if r['success'] and r['cpu_usage_total'] is not None]
    
    with open(os.path.join(result_dir, f"{algorithm}_results.txt"), 'w') as f:
        # 写入错误统计信息
        f.write(f"\n=== Error Statistics ===\n")
        f.write(f"Total runs: {total_runs}\n")
        f.write(f"Successful runs: {successful_runs}\n")
        f.write(f"Failed runs: {failed_runs}\n")
        f.write(f"Success rate: {success_rate:.2f}%\n")
        f.write(f"Error rate: {error_rate:.2f}%\n\n")

        # 写入性能统计信息
        if handshake_times:
            avg_handshake_time = sum(handshake_times) / len(handshake_times)
            f.write(f"Average handshake time for {algorithm}: {avg_handshake_time:.6f} seconds\n")
            f.write(f"All handshake times: {', '.join([f'{t:.6f}' for t in handshake_times])}\n")
            f.write(f"Min handshake time: {min(handshake_times):.6f} seconds\n")
            f.write(f"Max handshake time: {max(handshake_times):.6f} seconds\n")
            f.write(f"Standard deviation of handshake time: {np.std(handshake_times):.6f} seconds\n")
        
        if memory_usages:
            avg_memory = sum(memory_usages) / len(memory_usages)
            f.write(f"\nAverage memory usage for {algorithm}: {avg_memory:.2f} KB\n")
            f.write(f"All memory usages: {', '.join([f'{m:.2f}' for m in memory_usages])}\n")
            f.write(f"Min memory usage: {min(memory_usages):.2f} KB\n")
            f.write(f"Max memory usage: {max(memory_usages):.2f} KB\n")
            f.write(f"Standard deviation of memory usage: {np.std(memory_usages):.2f} KB\n")
        
        if cpu_usages:
            avg_cpu = sum(cpu_usages) / len(cpu_usages)
            f.write(f"\nAverage CPU usage (Per Core) for {algorithm}: {avg_cpu:.2f}%\n")
            f.write(f"All CPU usages (Per Core): {', '.join([f'{c:.2f}' for c in cpu_usages])}\n")
            f.write(f"Min CPU usage (Per Core): {min(cpu_usages):.2f}%\n")
            f.write(f"Max CPU usage (Per Core): {max(cpu_usages):.2f}%\n")
            f.write(f"Standard deviation of CPU usage (Per Core): {np.std(cpu_usages):.2f}%\n")
        
        if cpu_usages_total:
            avg_cpu_total = sum(cpu_usages_total) / len(cpu_usages_total)
            f.write(f"\nAverage CPU usage (Total) for {algorithm}: {avg_cpu_total:.2f}%\n")
            f.write(f"All CPU usages (Total): {', '.join([f'{c:.2f}' for c in cpu_usages_total])}\n")
            f.write(f"Min CPU usage (Total): {min(cpu_usages_total):.2f}%\n")
            f.write(f"Max CPU usage (Total): {max(cpu_usages_total):.2f}%\n")
            f.write(f"Standard deviation of CPU usage (Total): {np.std(cpu_usages_total):.2f}%\n")
        
        # 写入详细的错误信息
        failed_runs_data = [r for r in results if not r['success']]
        if failed_runs_data:
            f.write("\n=== Detailed Error Information ===\n")
            for i, failed_run in enumerate(failed_runs_data, 1):
                f.write(f"\nError #{i}:\n")
                f.write(failed_run['output'])
                f.write("\n" + "-"*50 + "\n")

        if client_output:
            f.write("\n--- Full Output ---\n")
            f.write(client_output)

    return {
        'total_runs': total_runs,
        'successful_runs': successful_runs,
        'failed_runs': failed_runs,
        'success_rate': success_rate,
        'error_rate': error_rate,
        'avg_handshake_time': avg_handshake_time if handshake_times else None,
        'min_handshake_time': min(handshake_times) if handshake_times else None,
        'max_handshake_time': max(handshake_times) if handshake_times else None,
        'std_handshake_time': np.std(handshake_times) if handshake_times else None,
        'handshake_times': handshake_times,
        'avg_memory': avg_memory if memory_usages else None,
        'min_memory': min(memory_usages) if memory_usages else None,
        'max_memory': max(memory_usages) if memory_usages else None,
        'std_memory': np.std(memory_usages) if memory_usages else None,
        'memory_usages': memory_usages,
        'avg_cpu': avg_cpu if cpu_usages else None,
        'min_cpu': min(cpu_usages) if cpu_usages else None,
        'max_cpu': max(cpu_usages) if cpu_usages else None,
        'std_cpu': np.std(cpu_usages) if cpu_usages else None,
        'cpu_usages': cpu_usages,
        'avg_cpu_total': avg_cpu_total if cpu_usages_total else None,
        'min_cpu_total': min(cpu_usages_total) if cpu_usages_total else None,
        'max_cpu_total': max(cpu_usages_total) if cpu_usages_total else None,
        'std_cpu_total': np.std(cpu_usages_total) if cpu_usages_total else None,
        'cpu_usages_total': cpu_usages_total
    }

def analyze_results(result_dir):
    results = {}
    for filename in os.listdir(result_dir):
        if filename.endswith('_results.txt'):
            algorithm = filename.rsplit('_', 1)[0]  # 支持带下划线的算法名
            filepath = os.path.join(result_dir, filename)
            try:
                with open(filepath, 'r') as f:
                    content = f.read()
                    # 解析错误统计信息
                    total_runs_match = re.search(r"Total runs: (\d+)", content)
                    failed_runs_match = re.search(r"Failed runs: (\d+)", content)
                    success_rate_match = re.search(r"Success rate: ([\d.]+)%", content)
                    error_rate_match = re.search(r"Error rate: ([\d.]+)%", content)
                    
                    # 解析性能指标
                    handshake_time_match = re.search(r"Average handshake time for .+: (.+) seconds", content)
                    memory_match = re.search(r"Average memory usage for .+: (.+) KB", content)
                    cpu_match = re.search(r"Average CPU usage \(Per Core\) for .+: (.+)%", content)
                    cpu_total_match = re.search(r"Average CPU usage \(Total\) for .+: (.+)%", content)
                    
                    if all([total_runs_match, failed_runs_match, success_rate_match, error_rate_match]):
                        total_runs = int(total_runs_match.group(1))
                        failed_runs = int(failed_runs_match.group(1))
                        success_rate = float(success_rate_match.group(1))
                        error_rate = float(error_rate_match.group(1))
                    else:
                        print(f"Could not find error statistics in {filename}")
                        continue
                    
                    # 提取所有测量数据
                    handshake_times_match = re.search(r"All handshake times: (.+)\n", content)
                    memory_usages_match = re.search(r"All memory usages: (.+)\n", content)
                    cpu_usages_match = re.search(r"All CPU usages \(Per Core\): (.+)\n", content)
                    cpu_total_usages_match = re.search(r"All CPU usages \(Total\): (.+)\n", content)
                    
                    if all([handshake_time_match, memory_match, cpu_match, cpu_total_match,
                           handshake_times_match, memory_usages_match, cpu_usages_match, cpu_total_usages_match]):
                        
                        handshake_times = [float(t) for t in handshake_times_match.group(1).split(', ')]
                        memory_usages = [float(m) for m in memory_usages_match.group(1).split(', ')]
                        cpu_usages = [float(c) for c in cpu_usages_match.group(1).split(', ')]
                        cpu_total_usages = [float(c) for c in cpu_total_usages_match.group(1).split(', ')]
                        
                        results[algorithm] = {
                            'total_runs': total_runs,
                            'failed_runs': failed_runs,
                            'success_rate': success_rate,
                            'error_rate': error_rate,
                            'avg_handshake_time': float(handshake_time_match.group(1)),
                            'min_handshake_time': min(handshake_times),
                            'max_handshake_time': max(handshake_times),
                            'std_handshake_time': np.std(handshake_times),
                            'handshake_times': handshake_times,
                            'avg_memory': float(memory_match.group(1)),
                            'min_memory': min(memory_usages),
                            'max_memory': max(memory_usages),
                            'std_memory': np.std(memory_usages),
                            'memory_usages': memory_usages,
                            'avg_cpu': float(cpu_match.group(1)),
                            'min_cpu': min(cpu_usages),
                            'max_cpu': max(cpu_usages),
                            'std_cpu': np.std(cpu_usages),
                            'cpu_usages': cpu_usages,
                            'avg_cpu_total': float(cpu_total_match.group(1)),
                            'min_cpu_total': min(cpu_total_usages),
                            'max_cpu_total': max(cpu_total_usages),
                            'std_cpu_total': np.std(cpu_total_usages),
                            'cpu_usages_total': cpu_total_usages
                        }
            except Exception as e:
                print(f"Error processing {filename}: {str(e)}")

    if results:
        # 创建DataFrame
        df = pd.DataFrame.from_dict(results, orient='index')
        
        # 创建图表函数
        def create_horizontal_bar_plot(data, title, xlabel, filename, stacked=False, colors=None):
            plt.figure(figsize=(12, max(8, len(data) * 0.3)))
            if stacked:
                # 堆叠条形图 (错误统计)
                bars = plt.barh(range(len(data[0])), data[0], label='Success', color=colors[0])
                bars_error = plt.barh(range(len(data[1])), data[1], left=data[0], label='Error', color=colors[1])
                for i in range(len(data[0])):
                    if data[0][i] > 0:
                        plt.text(data[0][i]/2, i, f'{data[0][i]:.1f}%', ha='center', va='center', color='white')
                    if data[1][i] > 0:
                        plt.text(data[0][i] + data[1][i]/2, i, f'{data[1][i]:.1f}%', ha='center', va='center', color='white')
                plt.legend()
            else:
                bars = plt.barh(range(len(data)), data.values)
                for bar in bars:
                    width = bar.get_width()
                    plt.text(width, bar.get_y() + bar.get_height()/2, 
                             f'{width:.2f}',
                             ha='left', va='center')
            
            plt.title(title)
            plt.xlabel(xlabel)
            plt.yticks(range(len(data) if not stacked else len(data[0])), 
                      data.index if not stacked else data[0].index)
            plt.tight_layout()
            plt.savefig(os.path.join(result_dir, filename))
            plt.close()

        # 绘制错误统计图
        success_rates = df['success_rate']
        error_rates = df['error_rate']
        create_horizontal_bar_plot(
            [success_rates, error_rates],
            'Handshake Success/Error Rates by Algorithm',
            'Percentage (%)',
            'handshake'
            'handshake_error_statistics.png',
            stacked=True,
            colors=['green', 'red']
        )

        # 绘制平均握手时间图
        create_horizontal_bar_plot(
            df['avg_handshake_time'], 
            'Average Handshake Time by Algorithm', 
            'Average Handshake Time (s)', 
            'avg_handshake_time.png'
        )

        # 绘制平均内存使用图
        create_horizontal_bar_plot(
            df['avg_memory'], 
            'Average Memory Usage by Algorithm', 
            'Average Memory Usage (KB)', 
            'avg_memory_usage.png'
        )

        # 绘制平均CPU使用率图(每核)
        create_horizontal_bar_plot(
            df['avg_cpu'], 
            'Average CPU Usage by Algorithm (Per Core)', 
            'Average CPU Usage (%)', 
            'avg_cpu_usage.png'
        )

        # 绘制总CPU使用率图
        create_horizontal_bar_plot(
            df['avg_cpu_total'], 
            'Average Total CPU Usage by Algorithm', 
            'Average Total CPU Usage (%)', 
            'avg_cpu_usage_total.png'
        )

        # 创建箱线图函数
        def create_horizontal_box_plot(data, title, xlabel, filename):
            plt.figure(figsize=(12, max(8, len(data['Algorithm'].unique()) * 0.3)))
            sns.boxplot(y=data['Algorithm'], x=data['Value'])
            plt.title(title)
            plt.xlabel(xlabel)
            plt.tight_layout()
            plt.savefig(os.path.join(result_dir, filename))
            plt.close()

        # 绘制握手时间分布图
        df_melted_handshake = pd.DataFrame(
            [(alg, time) for alg, data in results.items() for time in data['handshake_times']], 
            columns=['Algorithm', 'Value']
        )
        create_horizontal_box_plot(
            df_melted_handshake, 
            'Handshake Time Distribution by Algorithm', 
            'Handshake Time (s)', 
            'handshake_time_distribution.png'
        )

        # 绘制内存使用分布图
        df_melted_memory = pd.DataFrame(
            [(alg, mem) for alg, data in results.items() for mem in data['memory_usages']], 
            columns=['Algorithm', 'Value']
        )
        create_horizontal_box_plot(
            df_melted_memory, 
            'Memory Usage Distribution by Algorithm', 
            'Memory Usage (KB)', 
            'memory_usage_distribution.png'
        )

        # 绘制CPU使用率(每核)分布图
        df_melted_cpu = pd.DataFrame(
            [(alg, cpu) for alg, data in results.items() for cpu in data['cpu_usages']], 
            columns=['Algorithm', 'Value']
        )
        create_horizontal_box_plot(
            df_melted_cpu, 
            'CPU Usage Distribution by Algorithm (Per Core)', 
            'CPU Usage (%)', 
            'cpu_usage_distribution.png'
        )

        # 绘制总CPU使用率分布图
        df_melted_cpu_total = pd.DataFrame(
            [(alg, cpu) for alg, data in results.items() for cpu in data['cpu_usages_total']], 
            columns=['Algorithm', 'Value']
        )
        create_horizontal_box_plot(
            df_melted_cpu_total, 
            'Total CPU Usage Distribution by Algorithm', 
            'Total CPU Usage (%)', 
            'cpu_usage_total_distribution.png'
        )

        # 保存详细统计信息到CSV
        df_stats = df.drop(['handshake_times', 'memory_usages', 'cpu_usages', 'cpu_usages_total'], axis=1)
        df_stats.to_csv(os.path.join(result_dir, 'performance_statistics.csv'))

        # 输出每个算法的简要统计信息到summary.txt
        with open(os.path.join(result_dir, 'summary.txt'), 'w') as f:
            f.write("Performance Summary\n")
            f.write("==================\n\n")
            
            for algorithm in results:
                f.write(f"\n{algorithm}:\n")
                f.write("-" * (len(algorithm) + 1) + "\n")
                f.write(f"Success Rate: {results[algorithm]['success_rate']:.2f}%\n")
                f.write(f"Error Rate: {results[algorithm]['error_rate']:.2f}%\n")
                f.write(f"Average Handshake Time: {results[algorithm]['avg_handshake_time']:.6f}s\n")
                f.write(f"Average Memory Usage: {results[algorithm]['avg_memory']:.2f}KB\n")
                f.write(f"Average CPU Usage (Per Core): {results[algorithm]['avg_cpu']:.2f}%\n")
                f.write(f"Average Total CPU Usage: {results[algorithm]['avg_cpu_total']:.2f}%\n\n")

        print(f"Performance analysis completed. Results saved in {result_dir}")
    else:
        print("No valid results to analyze")







