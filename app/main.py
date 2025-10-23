from flask import Flask, jsonify, render_template, request
import subprocess, threading, time, re, os
import json
import grpc
from grpc_dir import ping_pb2, ping_pb2_grpc

IS_DOCKER = os.environ.get("IS_DOCKER", "false")
if IS_DOCKER in ["true", "True", "TRUE"]:
    print(" dockcer mode running")
    dns_file = os.environ.get("DNS_FILE", None)
    if dns_file is None:
        raise ValueError("DNS_FILE is not set")
    GRPC_TARGET = os.environ.get("GRPC_TARGET", None)
    if GRPC_TARGET is None:
        raise ValueError("GRPC_TARGET is not set")
else:
    print(" local mode running")
    import dotenv
    dotenv_path = os.path.join(os.path.dirname(__file__), ".env")
    if os.path.exists(dotenv_path):
        dotenv.load_dotenv(dotenv_path)
        dns_file = os.environ.get("DNS_FILE", "/etc/dnsmasq.d/local.conf")
        GRPC_TARGET = os.environ.get("GRPC_TARGET", "ping.grpc.sh:5555")
    else:
        dns_file = "/etc/dnsmasq.d/local.conf"
        GRPC_TARGET = "ping.grpc.sh:5555"


app = Flask(__name__)

status = {}

def grpc_ping(ip_list:list[str]) -> dict[str, bool]:
    try:
        with grpc.insecure_channel(GRPC_TARGET) as channel:
            stub = ping_pb2_grpc.PingServiceStub(channel)
            req = ping_pb2.PingRequest(ip_list=ip_list)
            resp = stub.CheckIPs(req, timeout=3)
            return {r.target: r.reachable for r in resp.results}
    except grpc.RpcError as e:
        print(f"[grpc_ping] RPC error: {e.code().name} - {e.details()}")
        return {ip: False for ip in ip_list}


def ping_host(ip) -> bool:
    """ 개별 실행은 사용안함 => GRPC 사용 """
    try:
        r = subprocess.run(
            ["ping", "-4", "-c", "1", "-W", "1", ip],
            capture_output=True, text=True
        )
        # ping 성공 문구 포함 시 alive=True
        alive = ("1 received" in r.stdout) or ("bytes from" in r.stdout)
        return alive
    except Exception as e:
        print( f"Error pinging host {ip}: {e}")
        return False



def k3s_health_check(host) -> bool:
    """호스트의 /k3s-health endpoint를 curl로 확인"""
    url = f"http://{host}/k3s-health"
    try:
        print(f"[k3s_health_check] Checking {url}")
        r = subprocess.run(["curl", "-s", url], capture_output=True, text=True, timeout=3)
        if r.returncode == 0:
            try:
                data = json.loads(r.stdout.strip())
                return data.get("health")
            except json.JSONDecodeError:
                return False
        return False
    except Exception as e:
        print(f"[k3s_health_check] Error: {e}")
        return False

def check_hosts():
    print("[check_hosts] start monitoring")
    while True:
        if not os.path.exists(dns_file):
            print(f"File not found: {dns_file}")
            time.sleep(10)
            continue

        vip_targets, service_targets, host_targets = [], [], []

        with open(dns_file) as f:
            for line in f:
                ### 여기서 분기 : local.conf(dnsmasq) 또는 custom.list(pihole)
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                # local.conf (dnsmasq 형식)
                if dns_file.endswith("local.conf"):
                    m = re.match(r'address=/(.+)/([\d\.]+)', line)
                    if not m:
                        continue
                    host, ip = m.groups()

                # custom.list (pihole 형식)
                elif dns_file.endswith("custom.list"):
                    m = re.match(r'([\d\.]+)\s+(.+)', line)
                    if not m:
                        continue
                    ip, host = m.groups()

                else:
                    continue

                if host == "VIP.service.sh":
                    vip_targets.append((host, ip))
                elif host.endswith(".service.sh"):
                    service_targets.append((host, ip))
                elif host.endswith(".host.sh"):
                    host_targets.append((host, ip))

        print(f"[check_hosts] vip_targets: {len(vip_targets)}")
        print(f"[check_hosts] service_targets: {len(service_targets)}")
        print(f"[check_hosts] host_targets: {len(host_targets)}")
        # gRPC ping for host targets only
        host_ips = [ip for _, ip in host_targets]
        grpc_results = grpc_ping(host_ips)

        for host, ip in vip_targets:
            alive = not ping_host(ip)  # ping 실패가 정상
            status[host] = {"ip": ip, "alive": alive, "type": "vip"}

        for host, ip in service_targets:
            alive = k3s_health_check(host)
            status[host] = {"ip": ip, "alive": alive, "type": "service"}

        for host, ip in host_targets:
            alive = grpc_results.get(ip, False)
            status[host] = {"ip": ip, "alive": alive, "type": "host"}

        # VIP 맨 앞으로 정렬
        status.update(dict(sorted(status.items(),
                                  key=lambda x: (x[1]["type"] != "vip", x[0]))))

        print("[status update]", status)
        time.sleep(10)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/status")
def get_status():
    return jsonify(status)

@app.route("/flask_status")
def get_flask_status():
    return jsonify({"status": "ok"})

@app.route("/manual_ping")
def manual_ping():
    return render_template("manual_ping.html")

@app.route("/grpc_ping", methods=["POST"])
def grpc_ping_route():
    data = request.get_json()
    targets = data.get("targets", [])
    result = grpc_ping(targets)
    return jsonify(result)

if __name__ == "__main__":
    threading.Thread(target=check_hosts, daemon=True).start()
    app.run(host="0.0.0.0", port=5000,debug=False)
