import os
import time
import psutil
from multiprocessing import Pool, cpu_count
from utility import (
    generate_cert_and_key, load_config, save_result, analyze_results,
    find_free_ports, print_debug_info, delete_network_namespaces, setup_network_namespaces, set_network_conditions, ping_server  # 引入新函数
)
from server import run_server
from client import run_client
import subprocess
import traceback

OPENSSL_PATH = "/usr/local/ssl/bin/openssl"


  
def run_single_benchmark(args):
    kem_algorithm, sig_algorithm, key_dir, port, run_number = args
    print(f"Run {run_number} for KEM: {kem_algorithm}, SIG: {sig_algorithm} on port {port}")
    
    server_process = None
    try:
        server_process = run_server(kem_algorithm, sig_algorithm, key_dir, port)
        if server_process is None:
            raise Exception(f"Failed to start server")
            
        print(f"Server started on port {port} with PID {server_process.pid}")
        time.sleep(1)
        cert_path = os.path.join(key_dir, "cert.pem")
        
        try:
            # 创建进程对象  # Create a process object
            process = psutil.Process()
            
            # 获取CPU逻辑核心数 # Get CPU logical core count
            cpu_count = psutil.cpu_count(logical=True)  # 获取逻辑核心数(包含超线程) # Get the number of logical cores (including hyper-threading)
            
            # 预热系统CPU测量 # Warm up the system CPU measurement
            process.cpu_percent()
            time.sleep(0.1)
            
            # 收集初始资源使用情况 # Collect initial resource usage
            start_time = time.process_time()
            initial_memory = process.memory_info().rss
            
            # 执行客户端操作 # Perform client operation
            handshake_time, output, client_pid = run_client(
                kem_algorithm, sig_algorithm, cert_path, port, timeout=10
            )
            
            # 收集最终资源使用情况 # Collect final resource usage
            end_time = time.process_time()
            final_memory = process.memory_info().rss
            
            # 计算CPU时间和使用率 # Calculate CPU time and usage
            process_time = end_time - start_time
            # 计算单核等效CPU使用率，除以逻辑核心数 # Calculate single-core equivalent CPU usage, divided by the number of logical cores
            cpu_usage = ((process_time / handshake_time) * 100 / cpu_count) if handshake_time and handshake_time > 0 else 0
            memory_usage = max(0, final_memory - initial_memory) / 1024  # KB
            
            # 验证握手是否成功 # Verify that the handshake was successful
            handshake_success = bool(output and (
                "Verify return code: 0 (ok)" in output or 
                "Handshake Complete" in output
            ))
            
            result = {
                'handshake_time': handshake_time if handshake_success else None,
                'output': output if run_number == 1 else None,
                'memory_usage': memory_usage,
                'cpu_usage': cpu_usage,
                'cpu_usage_total': cpu_usage * cpu_count,  # 保存总的CPU使用率 # Save the total CPU usage
                'process_time': process_time,
                'success': handshake_success,
                'client_pid': client_pid
            }
            
            if handshake_success:
                print(f"Handshake successful - Time: {handshake_time:.6f}s, "
                      f"Memory: {memory_usage:.2f}KB, CPU Usage(per core): {cpu_usage:.2f}%, "
                      f"CPU Usage(total): {cpu_usage * cpu_count:.2f}%, "
                      f"Process Time: {process_time:.6f}s")
            else:
                print(f"Handshake failed for run {run_number}")
            
            return result
            
        except psutil.Error as e:
            print(f"Resource monitoring error: {e}")
            return {
                'handshake_time': None,
                'output': f"Resource monitoring error: {str(e)}",
                'memory_usage': 0,
                'cpu_usage': 0,
                'cpu_usage_total': 0,
                'process_time': 0,
                'success': False,
                'client_pid': None
            }
            
    except Exception as e:
        print(f"Benchmark error: {str(e)}")
        traceback.print_exc()
        return {
            'handshake_time': None,
            'output': str(e),
            'memory_usage': 0,
            'cpu_usage': 0,
            'cpu_usage_total': 0,
            'process_time': 0,
            'success': False,
            'client_pid': None
        }
        
    finally:
        if server_process:
            try:
                server_process.terminate()
                server_process.wait(timeout=2)
            except:
                server_process.kill()

def run_benchmark(config_file, num_runs=200):
    try:
        # 运行基准测试前设置网络命名空间 # Set up network namespaces before running benchmarks
        print("Setting up network namespaces...")
        setup_network_namespaces()

        # 添加ping测试 # Add ping test
        ping_server()

        kem_algorithms, sig_algorithms, network_settings = load_config(config_file)
        
        # 读取网络设置 # Read network settings
        packet_loss = network_settings.get('packet_loss')
        bandwidth = network_settings.get('bandwidth')
        interface = network_settings.get('interface', 'veth0')
        
        if packet_loss is not None or bandwidth is not None:
            print("Applying network settings...")
            set_network_conditions(packet_loss=packet_loss, bandwidth=bandwidth, interface=interface)
        
        ping_server()
        loop_name = os.path.basename(config_file).split('.')[0]
        result_dir = f"results/{loop_name}"
        os.makedirs(result_dir, exist_ok=True)

        total_combinations = len(kem_algorithms) * len(sig_algorithms)
        all_ports = find_free_ports(total_combinations * num_runs)

        for kem_algorithm in kem_algorithms:
            for sig_algorithm in sig_algorithms:
                print(f"Benchmarking KEM: {kem_algorithm}, SIG: {sig_algorithm}")
                key_dir = os.path.join(result_dir, f"{kem_algorithm}_{sig_algorithm}")
                os.makedirs(key_dir, exist_ok=True)

                try:
                    generate_cert_and_key(key_dir, sig_algorithm)
                except Exception as e:
                    error_msg = f"Error generating cert and key for KEM: {kem_algorithm}, SIG: {sig_algorithm}: {str(e)}\n{traceback.format_exc()}"
                    print(error_msg)
                    with open(os.path.join(result_dir, f"{kem_algorithm}_{sig_algorithm}_error.log"), 'w') as f:
                        f.write(error_msg)
                    continue

                algorithm_ports = all_ports[:num_runs]
                all_ports = all_ports[num_runs:]

                run_args = [(kem_algorithm, sig_algorithm, key_dir, port, run+1) for run, port in enumerate(algorithm_ports)]

                with Pool(processes=min(cpu_count(), num_runs)) as pool:
                    results = pool.map(run_single_benchmark, run_args)

                # 初始化结果列表 # Initialize the result list
                successful_results = []
                client_output = None
                errors = []

                # 处理每次运行的结果 # Process the results of each run
                for run_result in results:
                    if run_result['success']:
                        if run_result['handshake_time'] is not None:
                            successful_results.append(run_result)
                        if run_result['output'] is not None and client_output is None:
                            client_output = run_result['output']
                    else:
                        errors.append(run_result['output'])

                # 保存结果 # Save the results
                if successful_results:
                    save_result(result_dir, f"{kem_algorithm}_{sig_algorithm}", successful_results, client_output)
                    
                    # 计算平均值用于显示 # Calculate averages for display
                    avg_handshake_time = sum(r['handshake_time'] for r in successful_results) / len(successful_results)
                    avg_memory = sum(r['memory_usage'] for r in successful_results) / len(successful_results)
                    avg_cpu = sum(r['cpu_usage'] for r in successful_results) / len(successful_results)
                    error_rate = (len(errors) / len(results)) * 100
                    
                    print(f"Results for KEM: {kem_algorithm}, SIG: {sig_algorithm}:")
                    print(f"Average handshake time: {avg_handshake_time:.6f} seconds")
                    print(f"Average memory usage: {avg_memory:.2f} KB")
                    print(f"Average CPU usage: {avg_cpu:.2f}%")
                    print(f"Error rate: {error_rate:.2f}%")
                    print(f"Successful runs: {len(successful_results)} out of {len(results)}")
                
                # 如果有错误，保存错误日志 # If there are errors, save the error log
                if errors:
                    error_log_path = os.path.join(result_dir, f"{kem_algorithm}_{sig_algorithm}_error.log")
                    with open(error_log_path, 'w') as f:
                        f.write(f"Total runs: {len(results)}\n")
                        f.write(f"Failed runs: {len(errors)}\n")
                        f.write(f"Success rate: {(1 - len(errors)/len(results))*100:.2f}%\n\n")
                        f.write("Detailed error messages:\n")
                        for i, error in enumerate(errors, 1):
                            f.write(f"\nError #{i}:\n{error}\n")
                            f.write("-" * 50 + "\n")
                    print(f"Errors occurred during benchmark. Check {error_log_path} for details.")

        analyze_results(result_dir)

    except Exception as e:
        print(f"Benchmark encountered an error: {str(e)}")
        traceback.print_exc()
    finally:
        # 清除网络设置 # Clear network settings
        print("Clearing network settings and network namespaces...")
        delete_network_namespaces()  # 确保命名空间被删除 # Ensure that the namespace is deleted
        print("Network cleanup completed.")

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: sudo python3 benchmark.py <config_file>")
        sys.exit(1)
    
    print_debug_info()
    run_benchmark(sys.argv[1])