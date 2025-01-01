import subprocess
import time
from typing import Tuple, Optional

OPENSSL_PATH = "/usr/local/ssl/bin/openssl"

ALGORITHM_MAPPING = {
    'kem': {},
    'sig': {
        'rsa:1024': 'rsa_pss_rsae_sha128',
        'rsa:2048': 'rsa_pss_rsae_sha256',
        'rsa:3072': 'rsa_pss_rsae_sha384',
        'rsa:4096': 'rsa_pss_rsae_sha512',
    }
}

def map_algorithm(alg_type: str, alg_name: str) -> str:
    """
    如果算法需要映射，则返回映射后的名称；否则返回原始名称
    """
    return ALGORITHM_MAPPING.get(alg_type, {}).get(alg_name, alg_name)

def run_client(kem_algorithm: str, sig_algorithm: str, cert_path: str, 
               port: int, timeout: int = 10) -> Tuple[Optional[float], str, Optional[int]]:
    """
    运行TLS客户端并执行握手
    
    Returns:
        Tuple[Optional[float], str, Optional[int]]: (握手时间, 输出信息, 进程PID)
    """
    mapped_kem = map_algorithm('kem', kem_algorithm)
    mapped_sig = map_algorithm('sig', sig_algorithm)
    
    command = [
        "ip", "netns", "exec", "client_ns",
        OPENSSL_PATH, "s_client",
        "-connect", f"10.200.1.1:{port}",
        "-tls1_3",
        "-groups", mapped_kem,
        "-sigalgs", mapped_sig,
        "-msg",
        "-servername", "localhost",
        "-CAfile", cert_path,
        "-provider", "oqsprovider",
        "-provider", "default"
    ]
    
    try:
        # 开始计时
        start_time = time.perf_counter()
        
        process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        # 返回进程PID以便在benchmark中监控
        process_pid = process.pid
        
        stdout, stderr = process.communicate(timeout=timeout)
        
        # 结束计时
        handshake_time = time.perf_counter() - start_time
        
        # 验证握手是否成功
        if "Verify return code: 0 (ok)" in stdout or "Handshake Complete" in stdout:
            return handshake_time, stdout, process_pid
        else:
            print(f"Handshake failed. stderr: {stderr}")
            return handshake_time, stdout + "\n" + stderr, process_pid
            
    except subprocess.TimeoutExpired as e:
        if 'process' in locals():
            process.kill()
            stdout, stderr = process.communicate()
        return None, f"Client connection timed out after {timeout} seconds", None
        
    except Exception as e:
        return None, str(e), None
        
    finally:
        if 'process' in locals():
            try:
                process.stdin.close()
                process.stdout.close()
                process.stderr.close()
            except:
                pass