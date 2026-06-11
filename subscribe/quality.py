# -*- coding: utf-8 -*-

# @Author  : wzdnzd
# @Time    : 2025-06-05

"""
IP 纯净度检测模块
核心功能：通过代理节点自身检测其真实出口 IP，
判断 IP 是否为机房/代理/VPS IP 还是真实住宅 IP，
并据此对节点优选排序。
"""

import ipaddress
import json
import os
import re
import socket
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional

import location
import utils
from logger import logger

# 已知机房 ASN
KNOWN_DATACENTER_ASNS = {
    14618, 16509, 39111, 8987, 15169, 19527, 396982, 41264,
    13335, 209242, 395747, 8075, 12076, 8068, 31898, 394351,
    14061, 203323, 62567, 20473, 215267, 63949, 16276, 24940,
    51167, 42473, 53667, 15395, 16265, 12876, 8560, 47502,
    22612, 26496, 37963, 45090, 136907, 55967, 135377,
    54113, 204429, 262254, 134204,
}

KNOWN_DATACENTER_CIDRS = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20",
    "162.158.0.0/15", "104.16.0.0/13", "172.64.0.0/13",
    "35.184.0.0/13", "35.192.0.0/14", "34.64.0.0/10",
    "52.0.0.0/10", "13.48.0.0/13", "54.192.0.0/12",
    "40.64.0.0/14", "52.224.0.0/11",
    "159.89.0.0/16", "159.203.0.0/16", "165.227.0.0/16",
    "167.99.0.0/16", "45.32.0.0/16", "108.61.0.0/16",
    "49.12.0.0/16", "65.108.0.0/16", "95.216.0.0/16",
    "136.243.0.0/16", "168.119.0.0/16",
]

HOSTING_KEYWORDS = [
    "cloud", "hosting", "datacenter", "data center", "server", "vps",
    "vds", "dedicated", "colo", "transit", "peering",
    "rackspace", "ovh", "hetzner", "contabo", "leaseweb",
    "digitalocean", "vultr", "linode", "scaleway", "online.net",
    "ionos", "cloudflare", "azure", "microsoft", "amazon", "aws", "ec2",
    "google cloud", "gcp", "gce", "oracle cloud", "oci",
    "alibaba cloud", "aliyun", "tencent cloud", "huawei cloud",
    "bare metal", "m247", "psychz", "sharktech", "multacom",
]

RESIDENTIAL_ISP_KEYWORDS = [
    "comcast", "charter", "spectrum", "cox", "verizon", "at&t", "centurylink",
    "frontier", "lumen", "telefonica", "deutsche telekom", "telecom italia",
    "orange", "bt", "virgin media", "sky uk", "talktalk",
    "singtel", "starhub", "m1", "tm net", "unifi", "true online",
    "chinanet", "chinaunicom", "china mobile", "cmcc", "cncgroup",
    "kddi", "softbank", "ntt", "ocn", "au one net", "so-net",
    "kt", "sk broadband", "lg u+", "kornet",
    "rogers", "bell canada", "shaw", "telus", "videotron",
    "optus", "telstra", "tpg",
    "vodafone", "o2", "three", "ee", "t-mobile",
]

IP_TYPE_RESIDENTIAL = "residential"
IP_TYPE_HOSTING = "hosting"
IP_TYPE_VPN = "vpn"
IP_TYPE_UNKNOWN = "unknown"


@dataclass
class IpPurityInfo:
    ip_address: str = ""
    asn: int = 0
    isp: str = ""
    org: str = ""
    country: str = ""
    ip_type: str = IP_TYPE_UNKNOWN
    is_datacenter: bool = False
    is_proxy: bool = False
    is_vpn: bool = False
    is_tor: bool = False
    fraud_score: float = -1.0
    purity_score: float = 0.0
    source: str = ""


@dataclass
class IpPurityResult:
    proxy_name: str
    proxy_type: str
    server: str
    port: int
    purity_info: Optional[IpPurityInfo] = None
    query_success: bool = False


def _is_ip_in_cidr(ip_str: str, cidr_list: list) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        for cidr_str in cidr_list:
            if ip in ipaddress.ip_network(cidr_str, strict=False):
                return True
        return False
    except (ValueError, ipaddress.AddressValueError):
        return False


def _resolve_ip(server: str) -> Optional[str]:
    if not server:
        return None
    try:
        ipaddress.ip_address(server)
        return server
    except ValueError:
        pass
    try:
        return socket.gethostbyname(server)
    except (socket.gaierror, OSError) as e:
        logger.debug(f"DNS resolution failed for {server}: {e}")
        return None


def _query_ip_api(ip: str, retry: int = 2) -> Optional[dict]:
    if not ip:
        return None
    url = f"http://ip-api.com/json/{ip}?fields=status,message,country,as,asname,isp,org,proxy,hosting,mobile"
    for attempt in range(max(1, retry)):
        try:
            req = urllib.request.Request(url=url)
            req.add_header("User-Agent", utils.USER_AGENT)
            resp = urllib.request.urlopen(req, timeout=10)
            data = json.loads(resp.read().decode("utf-8"))
            if data.get("status") == "success":
                return data
            if attempt < retry - 1:
                time.sleep(1)
        except Exception as e:
            if attempt < retry - 1:
                time.sleep(1)
                continue
            logger.debug(f"ip-api error for {ip}: {e}")
    return None


def _classify_ip_type(isp: str = "", org: str = "", asn: int = 0) -> str:
    text = f"{isp} {org}".lower()
    for kw in RESIDENTIAL_ISP_KEYWORDS:
        if kw in text:
            return IP_TYPE_RESIDENTIAL
    for kw in HOSTING_KEYWORDS:
        if kw in text:
            return IP_TYPE_HOSTING
    if asn > 0 and asn in KNOWN_DATACENTER_ASNS:
        return IP_TYPE_HOSTING
    return IP_TYPE_UNKNOWN


def _compute_purity_score(
    ip_type: str, is_datacenter: bool, is_proxy: bool,
    is_vpn: bool, is_tor: bool, fraud_score: float, is_in_known_cidr: bool,
) -> float:
    score = 1.0
    if ip_type == IP_TYPE_HOSTING:
        score -= 0.60
    elif ip_type == IP_TYPE_VPN:
        score -= 0.80
    if is_in_known_cidr:
        score -= 0.50
    if is_datacenter:
        score -= 0.30
    if is_proxy:
        score -= 0.40
    if is_vpn:
        score -= 0.40
    if is_tor:
        score -= 0.90
    if fraud_score > 0:
        score -= min(0.40, fraud_score * 0.005)
    return max(0.05, min(1.0, score))


def _get_real_ip_through_proxy(listener_port: int, retry: int = 2) -> Optional[str]:
    """通过代理监听端口访问 ip-api.com 获取真实出口 IP"""
    if not listener_port:
        return None
    for attempt in range(max(1, retry)):
        try:
            url = "http://ip-api.com/json/?fields=query"
            proxy_handler = urllib.request.ProxyHandler({
                "http": f"http://127.0.0.1:{listener_port}",
                "https": f"http://127.0.0.1:{listener_port}",
            })
            opener = urllib.request.build_opener(proxy_handler)
            req = urllib.request.Request(url=url)
            req.add_header("User-Agent", utils.USER_AGENT)
            resp = opener.open(req, timeout=15)
            data = json.loads(resp.read().decode("utf-8"))
            real_ip = data.get("query", "")
            if real_ip:
                return real_ip
        except Exception as e:
            if attempt < retry - 1:
                time.sleep(1)
    return None


def check_ip_purity_through_proxy(
    proxy: dict, listener_port: int = 0,
    use_scamalytics: bool = False, retry: int = 2,
    use_ipinfo: bool = False, ipinfo_token: str = "",
) -> IpPurityResult:
    """
    通过代理节点自身检测 IP 纯净度
    listener_port>0 时通过代理访问 ip-api.com 拿真实出口 IP，否则 DNS 解析回退
    """
    if not proxy or not isinstance(proxy, dict):
        return IpPurityResult(proxy_name="", proxy_type="", server="", port=0, query_success=False)

    proxy_name = proxy.get("name", "")
    proxy_type = proxy.get("type", "")
    server = proxy.get("server", "")
    port = int(proxy.get("port", 0))

    result = IpPurityResult(proxy_name=proxy_name, proxy_type=proxy_type, server=server, port=port)

    # 通过代理拿真实出口 IP，回退 DNS
    real_ip = None
    if listener_port and listener_port > 0:
        real_ip = _get_real_ip_through_proxy(listener_port, retry=retry)
    if not real_ip:
        real_ip = _resolve_ip(server)
    if not real_ip:
        result.query_success = False
        return result

    purity = IpPurityInfo(ip_address=real_ip)
    purity.is_datacenter = _is_ip_in_cidr(real_ip, KNOWN_DATACENTER_CIDRS)
    is_in_known_cidr = purity.is_datacenter

    ip_api_data = _query_ip_api(real_ip, retry=retry)
    if ip_api_data:
        as_str = ip_api_data.get("as", "")
        asn_match = re.search(r'AS(\d+)', str(as_str), re.IGNORECASE)
        if asn_match:
            purity.asn = int(asn_match.group(1))
        purity.isp = ip_api_data.get("isp", "")
        purity.org = ip_api_data.get("org", "")
        purity.country = ip_api_data.get("country", "")
        if ip_api_data.get("proxy", False):
            purity.is_proxy = True
        if ip_api_data.get("hosting", False):
            purity.is_datacenter = True
        if purity.asn > 0 and purity.asn in KNOWN_DATACENTER_ASNS:
            purity.is_datacenter = True
        purity.ip_type = _classify_ip_type(isp=purity.isp, org=purity.org, asn=purity.asn)
        if purity.is_proxy:
            purity.ip_type = IP_TYPE_VPN
        elif purity.is_datacenter and purity.ip_type == IP_TYPE_UNKNOWN:
            purity.ip_type = IP_TYPE_HOSTING
        purity.source = "ip-api"
    else:
        purity.ip_type = _classify_ip_type(isp=server, org="", asn=0)
        if is_in_known_cidr:
            purity.ip_type = IP_TYPE_HOSTING
            purity.is_datacenter = True
        purity.source = "heuristic"

    if use_scamalytics:
        try:
            url = f"https://scamalytics.com/ip/{real_ip}"
            req = urllib.request.Request(url=url)
            req.add_header("User-Agent", utils.USER_AGENT)
            resp = urllib.request.urlopen(req, timeout=15)
            html = resp.read().decode("utf-8", errors="replace")
            score_m = re.search(r'Fraud Score[^:]*:\s*(-?\d+)', html, re.IGNORECASE)
            if score_m:
                purity.fraud_score = float(score_m.group(1))
            risk_m = re.search(r'Risk\s*(Level|:)[^:]*:\s*(\w+)', html, re.IGNORECASE)
            if risk_m:
                risk_text = risk_m.group(2).lower()
                if "vpn" in risk_text:
                    purity.is_vpn = True
                if "proxy" in risk_text:
                    purity.is_proxy = True
        except Exception:
            pass

    if use_ipinfo and ipinfo_token and real_ip:
        try:
            url = f"https://ipinfo.io/{real_ip}?token={ipinfo_token}"
            req = urllib.request.Request(url=url)
            req.add_header("User-Agent", utils.USER_AGENT)
            resp = urllib.request.urlopen(req, timeout=15)
            data = json.loads(resp.read().decode("utf-8"))
            privacy = data.get("privacy", {})
            if privacy.get("tor", False):
                purity.is_tor = True
                purity.is_vpn = True
            if privacy.get("vpn", False):
                purity.is_vpn = True
            if privacy.get("proxy", False):
                purity.is_proxy = True
            if privacy.get("hosting", False):
                purity.is_datacenter = True
            # 补充 ASN（如果 ip-api 没拿到）
            if not purity.asn:
                asn_info = data.get("asn", {})
                if isinstance(asn_info, dict):
                    asn_str = asn_info.get("asn", "")
                    if asn_str:
                        asn_match = re.search(r'AS(\d+)', str(asn_str), re.IGNORECASE)
                        if asn_match:
                            purity.asn = int(asn_match.group(1))
                elif isinstance(asn_info, str):
                    asn_match = re.search(r'AS(\d+)', asn_info, re.IGNORECASE)
                    if asn_match:
                        purity.asn = int(asn_match.group(1))
            purity.source = "ip-api+ipinfo" if purity.source == "ip-api" else "ipinfo"
        except Exception:
            pass

    purity.purity_score = _compute_purity_score(
        ip_type=purity.ip_type, is_datacenter=purity.is_datacenter,
        is_proxy=purity.is_proxy, is_vpn=purity.is_vpn, is_tor=purity.is_tor,
        fraud_score=purity.fraud_score, is_in_known_cidr=is_in_known_cidr,
    )
    result.purity_info = purity
    result.query_success = True
    return result


def batch_check_ip_purity(
    proxies: list, use_scamalytics: bool = False,
    retry: int = 2, num_threads: int = 16,
    show_progress: bool = False,
    workspace: str = "", clash_bin: str = "",
    use_ipinfo: bool = False, ipinfo_token: str = "",
) -> dict[str, IpPurityResult]:
    """
    批量检测 IP 纯净度
    优先通过 mihomo 监听器走节点本身检测，回退 DNS 解析
    """
    if not proxies:
        return {}

    # 检查是否支持 mihomo 监听器
    use_listener = False
    mihomo_process = None
    port_map = {}
    purity_config_path = ""

    if workspace and clash_bin:
        try:
            from clash import is_mihomo
            use_listener = is_mihomo()
        except Exception:
            use_listener = False

    if use_listener:
        try:
            import yaml
            config, port_map = location.generate_mihomo_config(proxies)
            if config and port_map:
                os.makedirs(workspace, exist_ok=True)
                purity_config_path = os.path.join(workspace, "purity_config.yaml")
                with open(purity_config_path, "w+", encoding="utf8") as f:
                    yaml.dump(config, f, allow_unicode=True)
                utils.chmod(clash_bin)
                mihomo_process = subprocess.Popen([clash_bin, "-d", workspace, "-f", purity_config_path])
                time.sleep(random.randint(5, 8))
                logger.info(f"mihomo started with {len(port_map)} listeners for IP purity check")
        except Exception as e:
            logger.warning(f"mihomo listener mode failed: {e}, fallback to DNS")
            use_listener = False
            if mihomo_process:
                try:
                    mihomo_process.terminate()
                except Exception:
                    pass
                mihomo_process = None

    params = []
    for p in proxies:
        if not isinstance(p, dict) or not p.get("name", "") or not p.get("server", ""):
            continue
        name = p.get("name", "")
        lp = port_map.get(name, 0) if use_listener else 0
        params.append([p, lp, use_scamalytics, retry, use_ipinfo, ipinfo_token])

    if not params:
        return {}

    mode = "listener" if use_listener else "DNS"
    logger.info(f"IP purity check for {len(params)} proxies, mode: {mode}")

    results_list = utils.multi_thread_run(
        func=check_ip_purity_through_proxy,
        tasks=params, num_threads=num_threads, show_progress=show_progress,
    )

    if mihomo_process:
        try:
            mihomo_process.terminate()
            mihomo_process.wait(timeout=10)
        except Exception:
            try:
                mihomo_process.kill()
            except Exception:
                pass
        if purity_config_path and os.path.exists(purity_config_path):
            try:
                os.remove(purity_config_path)
            except Exception:
                pass
        for fname in ["cache.db"]:
            fp = os.path.join(workspace, fname)
            if os.path.exists(fp):
                try:
                    os.remove(fp)
                except Exception:
                    pass

    purity_map = {}
    for r in results_list:
        if r and isinstance(r, IpPurityResult) and r.proxy_name:
            purity_map[r.proxy_name] = r

    residential = sum(1 for r in purity_map.values() if r.purity_info and r.purity_info.ip_type == IP_TYPE_RESIDENTIAL)
    hosting = sum(1 for r in purity_map.values() if r.purity_info and r.purity_info.ip_type == IP_TYPE_HOSTING)
    vpn = sum(1 for r in purity_map.values() if r.purity_info and r.purity_info.ip_type == IP_TYPE_VPN)
    unknown = sum(1 for r in purity_map.values() if r.purity_info and r.purity_info.ip_type == IP_TYPE_UNKNOWN)
    logger.info(f"IP purity done: total={len(purity_map)}, res={residential}, hosting={hosting}, vpn={vpn}, unk={unknown}")
    return purity_map


def optimize_by_purity(
    proxies: list, purity_map: dict[str, IpPurityResult],
    drop_hosting: bool = False, drop_vpn: bool = True,
    purity_threshold: float = 0.0, top_ratio: float = 1.0,
) -> list:
    if not proxies or not purity_map:
        return proxies or []

    scored = []
    for p in proxies:
        name = p.get("name", "")
        result = purity_map.get(name)
        if not result or not result.query_success or not result.purity_info:
            scored.append((p, 0.0, IP_TYPE_UNKNOWN))
            continue
        purity = result.purity_info
        if drop_hosting and purity.ip_type == IP_TYPE_HOSTING:
            logger.debug(f"drop hosting: {name}, isp={purity.isp}")
            continue
        if drop_vpn and purity.ip_type == IP_TYPE_VPN:
            logger.debug(f"drop vpn: {name}, isp={purity.isp}")
            continue
        if purity.purity_score < purity_threshold:
            logger.debug(f"drop low purity: {name}, score={purity.purity_score:.4f}")
            continue
        scored.append((p, purity.purity_score, purity.ip_type))

    scored.sort(key=lambda x: (x[1], x[0].get("name", "")), reverse=True)
    if top_ratio < 1.0 and scored:
        keep = max(1, int(len(scored) * top_ratio))
        scored = scored[:keep]

    ordered = [item[0] for item in scored]

    # 节点名加类型标记
    name_map = {}
    for p, score, ip_type in scored:
        name = p.get("name", "")
        if name:
            tag = {"residential": "[HOME]", "hosting": "[DC]", "vpn": "[VPN]", "unknown": "[?]"}.get(ip_type, "[?]")
            stars = ""
            if score >= 0.8:
                stars = "*****"
            elif score >= 0.6:
                stars = "****"
            elif score >= 0.4:
                stars = "***"
            elif score >= 0.2:
                stars = "**"
            else:
                stars = "*"
            name_map[name] = f"{name} {tag}{stars}"

    for p in ordered:
        name = p.get("name", "")
        if name in name_map:
            p["name"] = name_map[name]

    dropped = len(proxies) - len(ordered)
    if dropped > 0:
        logger.info(f"purity optimize: keep {len(ordered)}, drop {dropped}")
    return ordered


@dataclass
class PurityConfig:
    enabled: bool = False
    use_scamalytics: bool = False
    retry: int = 2
    drop_hosting: bool = False
    drop_vpn: bool = True
    purity_threshold: float = 0.0
    top_ratio: float = 1.0
    inject_tags: bool = True
    use_ipinfo: bool = False
    ipinfo_token: str = ""

    @staticmethod
    def from_dict(data: dict) -> "PurityConfig":
        if not data:
            return PurityConfig()
        return PurityConfig(
            enabled=data.get("enabled", False),
            use_scamalytics=data.get("use_scamalytics", False),
            retry=max(1, int(data.get("retry", 2))),
            drop_hosting=data.get("drop_hosting", False),
            drop_vpn=data.get("drop_vpn", True),
            purity_threshold=min(1.0, max(0.0, float(data.get("purity_threshold", 0.0)))),
            top_ratio=min(1.0, max(0.01, float(data.get("top_ratio", 1.0)))),
            inject_tags=data.get("inject_tags", True),
            use_ipinfo=data.get("use_ipinfo", False),
            ipinfo_token=data.get("ipinfo_token", ""),
        )


def load_purity_config_from_env() -> PurityConfig:
    enabled = os.environ.get("PURITY_ENABLED", "").lower() in ["true", "1"]
    if not enabled:
        return PurityConfig(enabled=False)
    config = PurityConfig(enabled=True)
    try:
        config.use_scamalytics = os.environ.get("PURITY_USE_SCAMALYTICS", "").lower() in ["true", "1"]
        r = os.environ.get("PURITY_RETRY", "")
        if r: config.retry = max(1, int(r))
        config.drop_hosting = os.environ.get("PURITY_DROP_HOSTING", "").lower() in ["true", "1"]
        config.drop_vpn = os.environ.get("PURITY_DROP_VPN", "true").lower() not in ["false", "0"]
        t = os.environ.get("PURITY_THRESHOLD", "")
        if t: config.purity_threshold = min(1.0, max(0.0, float(t)))
        tr = os.environ.get("PURITY_TOP_RATIO", "")
        if tr: config.top_ratio = min(1.0, max(0.01, float(tr)))
        config.inject_tags = os.environ.get("PURITY_INJECT_TAGS", "true").lower() not in ["false", "0"]
        config.use_ipinfo = os.environ.get("PURITY_USE_IPINFO", "").lower() in ["true", "1"]
        token = os.environ.get("IPINFO_TOKEN", "")
        if token:
            config.ipinfo_token = token
    except (ValueError, TypeError):
        pass
    return config
