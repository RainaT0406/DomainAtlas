import subprocess
import time
import threading


def get_subdomains(domain, is_cancelled=None, timeout=300):
    """
    Get subdomains using Subfinder.
    
    Parameters
    ----------
    domain : str
        Target domain.
    is_cancelled : callable, optional
        Function that returns True if the scan should be cancelled.
    timeout : int, optional
        Maximum time in seconds to wait for Subfinder to complete.
    
    Returns
    -------
    list
        List of discovered subdomains.
    """
    
    try:
        print(f"[*] Starting Subfinder for {domain}...")
        
        # Start subprocess with Popen for better control
        process = subprocess.Popen(
            ["subfinder", "-d", domain, "-silent"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,  # Line buffered
        )
        
        # Store process reference for potential termination
        from backend.services.collection_service import _active_processes
        _active_processes.append(process)
        
        # Set up a flag for cancellation
        cancellation_flag = False
        
        def check_cancellation():
            nonlocal cancellation_flag
            while process.poll() is None:
                if is_cancelled and is_cancelled():
                    cancellation_flag = True
                    print("[!] Subfinder cancellation detected")
                    try:
                        process.terminate()
                        time.sleep(0.5)
                        if process.poll() is None:
                            process.kill()
                    except:
                        pass
                    break
                time.sleep(0.1)
        
        # Start cancellation monitoring thread
        monitor_thread = threading.Thread(target=check_cancellation, daemon=True)
        monitor_thread.start()
        
        # Wait for process with timeout
        start_time = time.time()
        subdomains = []
        
        # Read output line by line while process is running
        while process.poll() is None:
            # Check if cancelled
            if cancellation_flag:
                print("[!] Subfinder cancelled by user")
                if process in _active_processes:
                    _active_processes.remove(process)
                return []
            
            # Check timeout
            if time.time() - start_time > timeout:
                print(f"[!] Subfinder timed out after {timeout} seconds")
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
                if process in _active_processes:
                    _active_processes.remove(process)
                return []
            
            # Try to read a line
            try:
                line = process.stdout.readline()
                if line:
                    line = line.strip()
                    if line:
                        subdomains.append(line)
                else:
                    time.sleep(0.05)
            except Exception as e:
                print(f"[!] Error reading Subfinder output: {e}")
                break
        
        # Get remaining output
        try:
            remaining = process.stdout.read()
            if remaining:
                for line in remaining.strip().splitlines():
                    if line.strip():
                        subdomains.append(line.strip())
        except:
            pass
        
        # Process finished, get return code
        return_code = process.poll()
        
        # Remove from active processes
        if process in _active_processes:
            _active_processes.remove(process)
        
        # Check if cancelled
        if cancellation_flag:
            print("[!] Subfinder cancelled by user")
            return []
        
        # Check for errors
        if return_code != 0:
            stderr = process.stderr.read().strip()
            if stderr and "signal" not in stderr.lower():
                print(f"[!] Subfinder error: {stderr}")
            return []
        
        print(f"[+] Subfinder completed, found {len(subdomains)} subdomains")
        return subdomains

    except FileNotFoundError:
        print("[!] Subfinder not found. Please install subfinder.")
        return []
    except Exception as e:
        print(f"[!] Subfinder error: {e}")
        return []


if __name__ == "__main__":
    domain = input("Enter domain: ").strip()

    subdomains = get_subdomains(domain)

    print("\nSubdomains:")

    for subdomain in subdomains:
        print(f"  {subdomain}")