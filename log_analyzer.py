def find_ip(line):
    ip_start = line.find("ip=")
    if ip_start == -1:
        return
    ip_end = line.find(" ", ip_start)
    if ip_end == -1:
        ip_end = len(line)

    return line[ip_start+3:ip_end]


def analyze_logs(lines):
    login_failed = 0
    login_success = 0
    failed_ips = {}
    successful_ips = {}
    suspicious_ips = {}
    
    for line in lines:
        if "LOGIN_FAILED" in line:
            login_failed += 1
            
            ip = find_ip(line)
            if not ip:
                continue
            if ip in failed_ips:
                failed_ips[ip] += 1
            else:
                failed_ips[ip] = 1

        if "LOGIN_SUCCESS" in line:
            login_success += 1

            ip = find_ip(line)
            if not ip:
                continue
            if ip in successful_ips:
                successful_ips[ip] += 1
            else:
                successful_ips[ip] = 1

    for ip, count in failed_ips.items():
        if count >= 3:
            suspicious_ips[ip] = True

    return login_failed, login_success, failed_ips, successful_ips, suspicious_ips



logfile = input("Enter log file: ")
    
with open(logfile, "r") as f:
    content = f.read()
    lines = content.splitlines()
    
    login_failed, login_success, failed_ips, successful_ips, suspicious_ips = analyze_logs(lines)
    print("Successful login attempts:", login_success)
    print("Failed login attempts:", login_failed)

    if len(failed_ips) > 0 or len(successful_ips) > 0:
        ips = set(list(failed_ips) + list(successful_ips))
        for ip in ips:
            print(ip+": ", failed_ips.get(ip, 0), "failed", successful_ips.get(ip,0), "successful")

    if len(suspicious_ips) > 0:
        print("Suspicious IPs:")
        for i,v in suspicious_ips.items():
            print(i, "-", failed_ips[i], "failed attempts")

