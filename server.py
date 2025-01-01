
import subprocess
import time
import os
import re
import threading
OPENSSL_PATH = "/usr/local/ssl/bin/openssl"

ALGORITHM_MAPPING = {
    'kem': {
        # 保持原样，因为没有 KEM 算法映射
    },
    'sig': {
        'rsa:1024': 'rsa_pss_rsae_sha128',
        'rsa:2048': 'rsa_pss_rsae_sha256',
        'rsa:3072': 'rsa_pss_rsae_sha384',
        'rsa:4096': 'rsa_pss_rsae_sha512',
    }
}

def map_algorithm(alg_type, alg_name):
    """
    如果算法需要映射，则返回映射后的名称；否则返回原始名称
    """
    return ALGORITHM_MAPPING.get(alg_type, {}).get(alg_name, alg_name)

def run_server(kem_algorithm, sig_algorithm, key_dir, port):
    cert_file = os.path.join(key_dir, "cert.pem")
    key_file = os.path.join(key_dir, "key.pem")
    
    # 使用映射函数来获取正确的算法名称
    mapped_kem = map_algorithm('kem', kem_algorithm)
    mapped_sig = map_algorithm('sig', sig_algorithm)
    
    command = [
        "ip", "netns", "exec", "server_ns",
        "/usr/local/ssl/bin/openssl", "s_server",
        "-accept", f"{port}",
        "-cert", cert_file,
        "-key", key_file,
        "-www",
        "-tls1_3",
        "-groups", mapped_kem,
        "-sigalgs", mapped_sig,
        "-provider", "oqsprovider",
        "-provider", "default"
    ]

    try:
        print(f"Starting server with command: {' '.join(command)}")
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        # 等待服务器启动
        time.sleep(2)
        
        # 检查服务器是否成功启动
        if process.poll() is not None:
            stdout, stderr = process.communicate()
            print(f"Server failed to start on port {port}. Return code: {process.returncode}")
            print(f"Server stdout: {stdout}")
            print(f"Server stderr: {stderr}")
            return None
        
        print(f"Server started on port {port} with PID {process.pid}")
        return process
    except Exception as e:
        print(f"Exception while starting server on port {port}: {str(e)}")
        return None

# 添加一个用于验证服务器是否正在运行的函数
def is_server_running(process):
    return process is not None and process.poll() is None

# 如果需要，可以添加一个关闭服务器的函数
def stop_server(process):
    if process:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
