#!/usr/bin/env python3
import argparse
import os
import subprocess
import sys
import time
from multiprocessing import Process, Queue, Value, Lock
from pathlib import Path
from threading import Thread

"""
Parallel LUKS Bruteforce using cryptsetup directly (no Hashcat/JtR).
- Uses multiprocessing to distribute wordlist across workers
- Optional GPU selection for each process (useful if using GPU-accelerated libraries)
- Iterates a wordlist and runs: cryptsetup open --test-passphrase (or luksOpen with --test-passphrase)
- Stops on first success and prints the found passphrase.
- Does NOT map the device; only tests passphrase.

Requirements:
- Run with root privileges (sudo), because cryptsetup typically requires it.
- cryptsetup must support --test-passphrase for your LUKS version.

Usage:
  sudo python3 tools/brute_force/cryptsetup_bruteforce.py --device /dev/sdb1 --wordlist ./wordlist.txt
  # With parallel workers:
  sudo python3 tools/brute_force/cryptsetup_bruteforce.py --device /dev/sdb1 --wordlist ./wordlist.txt --workers 4
  # With GPU selection (if using GPU libraries):
  sudo python3 tools/brute_force/cryptsetup_bruteforce.py --device /dev/sdb1 --wordlist ./wordlist.txt --workers 2 --gpu-selection
"""

def detect_gpus():
    """Detect available GPUs (NVIDIA CUDA and OpenCL)"""
    gpus = []
    
    # Try NVIDIA GPUs first
    try:
        result = subprocess.run(['nvidia-smi', '--list-gpus'], capture_output=True, text=True)
        if result.returncode == 0:
            for i, line in enumerate(result.stdout.strip().split('\n')):
                if 'GPU' in line:
                    gpus.append(f"CUDA GPU {i}: {line.split(': ')[1]}")
    except FileNotFoundError:
        pass
    
    # Try OpenCL devices
    try:
        import pyopencl as cl
        platforms = cl.get_platforms()
        for p_idx, platform in enumerate(platforms):
            devices = platform.get_devices()
            for d_idx, device in enumerate(devices):
                gpu_name = f"OpenCL {p_idx}.{d_idx}: {device.name.strip()}"
                if gpu_name not in [g for g in gpus if 'OpenCL' in g]:
                    gpus.append(gpu_name)
    except ImportError:
        pass
    
    return gpus


def select_gpu_menu():
    """Interactive GPU selection menu"""
    gpus = detect_gpus()
    
    if not gpus:
        print("[!] No GPUs detected. Running on CPU only.")
        return None
    
    print("\n=== GPU Selection Menu ===")
    print("0. CPU only (no GPU)")
    for i, gpu in enumerate(gpus, 1):
        print(f"{i}. {gpu}")
    
    while True:
        try:
            choice = int(input("\nSelect GPU (0 for CPU): "))
            if choice == 0:
                return None
            elif 1 <= choice <= len(gpus):
                selected_gpu = choice - 1
                print(f"[+] Selected: {gpus[selected_gpu]}")
                return selected_gpu
            else:
                print(f"[!] Invalid choice. Enter 0-{len(gpus)}")
        except ValueError:
            print("[!] Please enter a number")


def run_cmd(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


def test_passphrase(device: str, passphrase: str, luks_type: str | None = None, gpu_id: int | None = None) -> bool:
    """Test a single passphrase against LUKS device"""
    # Set GPU environment if specified
    if gpu_id is not None:
        os.environ["CUDA_VISIBLE_DEVICES"] = str(gpu_id)
        # Optional: Set OpenCL device if using pyopencl
        os.environ["PYOPENCL_DEVICE"] = str(gpu_id)
    
    # Prefer 'cryptsetup open --test-passphrase' (does not create mapping)
    cmd = ["cryptsetup", "open", "--test-passphrase"]
    if luks_type:
        cmd += ["--type", luks_type]
    # Device at end; passphrase via stdin
    cmd += [device, "test_mapper"]  # mapper name is ignored in --test-passphrase
    proc = subprocess.run(
        cmd,
        input=passphrase + "\n",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if proc.returncode == 0:
        return True
    # Some versions only support --test-passphrase on luksOpen, try alternative
    alt = ["cryptsetup", "luksOpen", "--test-passphrase"]
    if luks_type:
        alt += ["--type", luks_type]
    alt += [device, "test_mapper"]
    proc2 = subprocess.run(
        alt,
        input=passphrase + "\n",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return proc2.returncode == 0


def worker_process(worker_id: int, device: str, luks_type: str | None, password_queue: Queue, 
                  result_queue: Queue, found_flag: Value, counter_lock: Lock, 
                  total_attempts: Value, gpu_id: int | None = None):
    """Worker process that tests passphrases from queue"""
    print(f"[+] Worker {worker_id} started (GPU: {gpu_id if gpu_id is not None else 'CPU'})")
    
    # Set GPU for this process if specified
    if gpu_id is not None:
        os.environ["CUDA_VISIBLE_DEVICES"] = str(gpu_id)
        os.environ["PYOPENCL_DEVICE"] = str(gpu_id)
    
    local_attempts = 0
    
    while True:
        try:
            # Check if password already found
            with found_flag.get_lock():
                if found_flag.value:
                    break
            
            # Get password from queue (timeout to check found_flag periodically)
            try:
                password = password_queue.get(timeout=1)
                if password is None:  # Sentinel value to stop
                    break
            except:
                continue
            
            # Test the password
            success = test_passphrase(device, password, luks_type, gpu_id)
            local_attempts += 1
            
            # Update global counter
            with counter_lock:
                total_attempts.value += 1
                if total_attempts.value % 1000 == 0:
                    print(f"[-] Total attempts: {total_attempts.value}")
            
            if success:
                with found_flag.get_lock():
                    if not found_flag.value:  # First to find it
                        found_flag.value = 1
                        result_queue.put(password)
                        print(f"[+] SUCCESS by Worker {worker_id}: passphrase found -> {password}")
                break
                
        except Exception as e:
            print(f"[!] Worker {worker_id} error: {e}")
            continue
    
    print(f"[-] Worker {worker_id} finished ({local_attempts} local attempts)")


def distribute_passwords(wordlist_path: Path, password_queue: Queue, chunk_size: int = 1000):
    """Read wordlist and distribute passwords to queue"""
    print(f"[+] Loading wordlist: {wordlist_path}")
    
    with wordlist_path.open("r", encoding="utf-8", errors="ignore") as f:
        batch = []
        for line in f:
            pw = line.rstrip("\n\r")
            if not pw:
                continue
            
            batch.append(pw)
            if len(batch) >= chunk_size:
                for password in batch:
                    password_queue.put(password)
                batch = []
        
        # Add remaining passwords
        for password in batch:
            password_queue.put(password)
    
    print(f"[+] Wordlist loaded into queue")


def main():
    ap = argparse.ArgumentParser(description="Parallel LUKS Bruteforce using cryptsetup")
    ap.add_argument("--device", required=True, help="LUKS device path, e.g., /dev/sdb1")
    ap.add_argument("--wordlist", required=True, help="Path to wordlist file")
    ap.add_argument("--type", dest="luks_type", default=None, help="LUKS type hint (e.g., luks2 or luks)")
    ap.add_argument("--max", dest="max_attempts", type=int, default=0, help="Max attempts (0 = no limit)")
    ap.add_argument("--workers", type=int, default=1, help="Number of parallel workers (default: 1)")
    ap.add_argument("--gpu-selection", action="store_true", help="Show GPU selection menu")
    ap.add_argument("--gpu", type=int, default=None, help="Force specific GPU ID (0,1,2...)")
    args = ap.parse_args()

    device = args.device
    wl_path = Path(args.wordlist)
    luks_type = args.luks_type
    max_attempts = args.max_attempts
    num_workers = args.workers
    gpu_selection = args.gpu_selection
    force_gpu = args.gpu

    if not wl_path.exists():
        print(f"[x] Wordlist not found: {wl_path}", file=sys.stderr)
        sys.exit(2)

    print(f"[+] Target device: {device}")
    print(f"[+] Wordlist: {wl_path}")
    print(f"[+] Workers: {num_workers}")
    if luks_type:
        print(f"[+] LUKS type hint: {luks_type}")

    # GPU Selection
    selected_gpu = None
    if gpu_selection and force_gpu is None:
        selected_gpu = select_gpu_menu()
    elif force_gpu is not None:
        selected_gpu = force_gpu
        print(f"[+] Using GPU {force_gpu}")

    # Single worker mode (original behavior)
    if num_workers == 1:
        print("[+] Running in single-worker mode")
        attempts = 0
        with wl_path.open("r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                pw = line.rstrip("\n\r")
                if not pw:
                    continue
                attempts += 1
                if max_attempts and attempts > max_attempts:
                    print(f"[!] Max attempts reached: {max_attempts}")
                    break
                ok = test_passphrase(device, pw, luks_type, selected_gpu)
                if ok:
                    print(f"[+] SUCCESS: passphrase found -> {pw}")
                    sys.exit(0)
                else:
                    if attempts % 1000 == 0:
                        print(f"[-] Tried {attempts} passwords...")
        print("[x] No passphrase found in provided wordlist")
        sys.exit(1)

    # Multi-worker mode
    print(f"[+] Starting {num_workers} parallel workers...")
    
    # Create shared resources
    password_queue = Queue(maxsize=10000)  # Buffer for passwords
    result_queue = Queue()
    found_flag = Value('i', 0)  # Shared flag to signal when password is found
    counter_lock = Lock()
    total_attempts = Value('i', 0)
    
    # Start password loader thread
    loader_thread = Thread(target=distribute_passwords, args=(wl_path, password_queue))
    loader_thread.daemon = True
    loader_thread.start()
    
    # Start worker processes
    workers = []
    for worker_id in range(num_workers):
        # Distribute GPUs round-robin if using GPU
        worker_gpu = selected_gpu if selected_gpu is not None else None
        if selected_gpu is not None and num_workers > 1:
            # For multiple workers, distribute across available GPUs
            gpus = detect_gpus()
            if gpus:
                worker_gpu = worker_id % len(gpus)
        
        worker = Process(
            target=worker_process,
            args=(worker_id, device, luks_type, password_queue, result_queue, 
                  found_flag, counter_lock, total_attempts, worker_gpu)
        )
        worker.start()
        workers.append(worker)
    
    # Monitor for results
    start_time = time.time()
    try:
        while loader_thread.is_alive() or not password_queue.empty():
            # Check if password found
            if found_flag.value:
                try:
                    found_password = result_queue.get(timeout=1)
                    print(f"\n[+] PASSWORD FOUND: {found_password}")
                    elapsed = time.time() - start_time
                    print(f"[+] Total time: {elapsed:.2f} seconds")
                    print(f"[+] Total attempts: {total_attempts.value}")
                    
                    # Signal all workers to stop
                    for _ in range(num_workers):
                        password_queue.put(None)  # Sentinel values
                    
                    # Wait for workers to finish
                    for worker in workers:
                        worker.join(timeout=5)
                        if worker.is_alive():
                            worker.terminate()
                    
                    sys.exit(0)
                except:
                    break
            
            time.sleep(0.5)
        
        # No password found - wait for workers to finish
        print("[+] Wordlist exhausted, waiting for workers to finish...")
        for _ in range(num_workers):
            password_queue.put(None)  # Send stop signals
        
        for worker in workers:
            worker.join()
        
        elapsed = time.time() - start_time
        print(f"\n[x] No passphrase found in wordlist")
        print(f"[+] Total time: {elapsed:.2f} seconds")
        print(f"[+] Total attempts: {total_attempts.value}")
        sys.exit(1)
        
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
        # Terminate all workers
        for worker in workers:
            worker.terminate()
        sys.exit(130)


if __name__ == "__main__":
    main()
