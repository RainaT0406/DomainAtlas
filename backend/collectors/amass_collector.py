import re
import subprocess
import time
import threading


def get_amass_subdomains(domain, is_cancelled=None, timeout=300):
    """
    Get subdomains using Amass (passive mode).

    Parameters
    ----------
    domain : str
        Target domain.
    is_cancelled : callable, optional
        Function that returns True if the scan should be cancelled.
    timeout : int, optional
        Maximum time in seconds to wait for Amass to complete.

    Returns
    -------
    list
        List of discovered subdomains.
    """

    try:

        print("[*] Running Amass...")

        # Start subprocess with Popen for better control
        process = subprocess.Popen(
            ["amass", "enum", "-passive", "-d", domain],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,  # Line buffered
        )

        # Store process reference for potential termination
        from backend.services.collection_service import _active_processes
        _active_processes.append(process)

        # Set up a thread to check for cancellation
        cancellation_flag = False
        
        def check_cancellation():
            nonlocal cancellation_flag
            while process.poll() is None:
                if is_cancelled and is_cancelled():
                    cancellation_flag = True
                    print("[!] Amass cancellation detected")
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
        output_lines = []
        
        # Read output with timeout
        while process.poll() is None:
            # Check if cancelled
            if cancellation_flag:
                print("[!] Amass cancelled by user")
                if process in _active_processes:
                    _active_processes.remove(process)
                return []
            
            # Check timeout
            if time.time() - start_time > timeout:
                print(f"[!] Amass timed out after {timeout} seconds")
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
                    output_lines.append(line)
                else:
                    time.sleep(0.05)
            except Exception as e:
                print(f"[!] Error reading Amass output: {e}")
                break

        # Get remaining output
        try:
            remaining = process.stdout.read()
            if remaining:
                output_lines.append(remaining)
        except:
            pass

        # Process finished, get return code
        return_code = process.poll()

        # Remove from active processes
        if process in _active_processes:
            _active_processes.remove(process)

        # Check if cancelled
        if cancellation_flag:
            print("[!] Amass cancelled by user")
            return []

        # Check for errors
        if return_code != 0 and return_code is not None:
            stderr = process.stderr.read().strip()
            if stderr and "signal" not in stderr.lower():
                print(f"[!] Amass error: {stderr}")
            return []

        # Combine all output lines
        output = "".join(output_lines)

        subdomains = set()

        # Remove ANSI terminal color/control sequences
        ansi_escape = re.compile(
            r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])"
        )

        output = ansi_escape.sub(
            "",
            output
        )

        for line in output.splitlines():

            line = line.strip()

            if not line:
                continue

            # Skip informational lines
            if "Starting enumeration" in line:
                continue
            if "Identified" in line and "domains" in line:
                continue
            if "Building" in line and "graph" in line:
                continue
            
            if " (FQDN) --> " not in line:
                continue

            source = line.split(
                " (FQDN) --> ",
                1
            )[0].strip()

            if (
                source.endswith(f".{domain}")
                and source != domain
            ):
                subdomains.add(source)

        print(
            f"[+] Amass found: {len(subdomains)}"
        )

        return sorted(subdomains)

    except FileNotFoundError:

        print(
            "[!] Amass executable not found."
        )

        print(
            "[!] Continuing without Amass."
        )

        return []

    except Exception as error:

        print(
            f"[!] Amass failed: {error}"
        )

        print(
            "[!] Continuing without Amass."
        )

        return []