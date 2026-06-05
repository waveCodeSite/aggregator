# -*- coding: utf-8 -*-

# @Author  : wzdnzd
# @Time    : 2025-06-05

"""
IP 纯净度检测模块
核心功能：检测代理节点的 IP 是否为机房/代理/VPS IP（"不干净"），
还是真实住宅/原生 IP（"纯净"），并据此对节点优选排序。
纯净度高的 IP 不易被目标服务（如 ChatGPT、Netflix、银行网站等）识别并拦截。
"""

import ipaddress
import json
import os
import re
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional

import utils
from logger import logger

# ============================================================
# 已知机房/云服务商 ASN 列表
# 这些 ASN 的 IP 基本可以判定为机房 IP（非住宅）
# ============================================================
KNOWN_DATACENTER_ASNS = {
    # AWS
    14618, 16509, 39111, 8987, 17493, 31708, 38895, 64510, 7224, 9059,
    # Google Cloud / GCP
    15169, 19527, 396982, 41264, 36384, 36429, 36492, 396356, 396361,
    # Cloudflare
    13335, 209242, 395747, 203898, 14789, 55293, 200242,
    # Microsoft Azure
    8075, 12076, 8068, 8069, 8070, 8071, 8072, 8073, 8074, 8076, 8077, 8078, 8079,
    # Oracle Cloud
    31898, 394351, 395962,
    # DigitalOcean
    14061, 203323, 62567,
    # Vultr
    20473, 215267,
    # Linode / Akamai
    63949, 16787, 16955, 22244, 398993,
    # Hetzner
    24940, 213230,
    # OVH / SoYouStart / Kimsufi
    16276, 35540, 21409, 42298, 45062,
    # Hetzner Online
    24940,
    # Contabo
    51167, 42473,
    # BuyVM / FranTech
    53667, 394380,
    # Rackspace
    15395, 19994, 33017, 33876,
    # Leaseweb
    16265, 28753, 396356,
    # Online.net / Scaleway
    12876, 29462, 46966,
    # Gandi
    59253, 207371,
    # IONOS / 1&1
    8560, 47447, 197068, 211252,
    # Hostinger
    47502, 163253,
    # Namecheap
    22612, 397315,
    # GoDaddy
    26496, 398101, 44273,
    # Alibaba Cloud
    37963, 45011, 17713, 45102,
    # Tencent Cloud
    45090, 132203, 136970,
    # Huawei Cloud
    136907, 55967, 136900,
    # Baidu Cloud
    55992,
    # UCloud
    135377,
    # Vercel
    134204,
    # Fly.io
    204429,
    # Railway
    262254,
    # Cloudflare Warp
    209242,
    # ArvanCloud
    200395, 202835, 205431, 206745, 208573, 209751, 210030, 210157, 211529, 213035, 213296, 398432,
    # Fastly
    54113,
    # Akamai / Linode
    12222, 16625, 20940, 21342, 21399, 22207, 22363, 23454, 23455, 23597, 23903, 24363, 25607, 25723, 26419, 27304,
    30675, 31108, 31109, 31110, 32338, 3257, 32787, 33287, 33905, 34164, 34893, 35204, 35819, 35993, 35994, 35995,
    36183, 36229, 36903, 37284, 393610, 393618, 397373, 398102, 398721, 40029, 40320, 40509, 40732, 40807, 40868,
    40994, 41213, 41905, 42052, 42086, 42428, 42561, 43066, 43358, 43735, 43971, 44156, 44444, 44758, 44859, 45168,
    45424, 45519, 45631, 45915, 46072, 46157, 46378, 46464, 46480, 46786, 46884, 46968, 47224, 47246, 47580, 47764,
    47884, 48033, 48063, 48119, 48184, 48771, 48847, 49585, 49591, 49611, 49928, 49937, 49945, 49984, 50013, 50166,
    50265, 50489, 50631, 50644, 50678, 50792, 50850, 50870, 50877, 51088, 51211, 51369, 51474, 51764, 51773, 51830,
    51848, 51938, 52049, 52438, 52531, 52790, 52862, 52897, 53097, 53122, 53490, 53515, 53625, 53717, 53794, 53852,
    53924, 53928, 53956, 53987, 54039, 54082, 54127, 54134, 54284, 54321, 54356, 54643, 54786, 54800, 54978, 54999,
    55044, 55163, 55290, 55321, 55341, 55419, 55463, 55465, 55501, 55604, 55613, 55715, 55783, 55818, 55852, 55920,
    55974, 56007, 56082, 56135, 56148, 56228, 56267, 56333, 56380, 56474, 56529, 56538, 56589, 56595,
}

# ============================================================
# 已知机房/云服务商 CIDR 范围
# 这些 IP 段直接判定为机房 IP
# 只包含最常用的，更多依赖 ASN 检测
# ============================================================
KNOWN_DATACENTER_CIDRS = [
    # Cloudflare
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    # Google Cloud
    "35.184.0.0/13", "35.192.0.0/14", "35.196.0.0/15", "35.224.0.0/13",
    "35.240.0.0/13", "34.64.0.0/10", "34.128.0.0/10",
    # AWS
    "52.0.0.0/10", "52.64.0.0/11", "52.96.0.0/12", "52.112.0.0/14",
    "52.124.0.0/15", "54.144.0.0/12", "54.160.0.0/14", "54.192.0.0/12",
    "13.48.0.0/13", "13.56.0.0/13", "13.124.0.0/14", "13.208.0.0/14",
    # Azure
    "40.64.0.0/14", "40.112.0.0/14", "40.124.0.0/14", "52.224.0.0/11",
    "52.160.0.0/11", "52.136.0.0/13",
    # DigitalOcean
    "159.89.0.0/16", "159.203.0.0/16", "165.227.0.0/16", "167.99.0.0/16",
    "157.230.0.0/16", "138.197.0.0/16", "138.68.0.0/16", "104.248.0.0/16",
    "178.62.0.0/16", "128.199.0.0/16", "107.170.0.0/16", "162.243.0.0/16",
    # Vultr
    "45.32.0.0/16", "108.61.0.0/16", "136.244.0.0/16", "149.28.0.0/16",
    "155.138.0.0/16", "207.148.0.0/16", "209.222.0.0/16",
    # Hetzner
    "49.12.0.0/16", "49.13.0.0/16", "65.108.0.0/16", "65.109.0.0/16",
    "78.46.0.0/15", "88.198.0.0/16", "91.190.0.0/16", "94.130.0.0/16",
    "95.216.0.0/16", "116.202.0.0/16", "135.181.0.0/16", "136.243.0.0/16",
    "138.201.0.0/16", "142.132.0.0/16", "144.76.0.0/16", "148.251.0.0/16",
    "157.90.0.0/16", "159.69.0.0/16", "162.55.0.0/16", "167.235.0.0/16",
    "168.119.0.0/16", "171.22.0.0/16", "172.86.0.0/16", "178.63.0.0/16",
    "188.40.0.0/16", "192.162.0.0/16", "195.201.0.0/16", "213.239.0.0/16",
]

# ============================================================
# 已知 VPN/代理/出口 IP 特征关键词
# 如果 ISP/org 名称包含这些词，判定为非住宅 IP
# ============================================================
HOSTING_KEYWORDS = [
    "cloud", "hosting", "datacenter", "data center", "server", "vps",
    "vds", "dedicated", "colo", "colo-cation", "transit", "peering",
    "rack", "rackspace", "ovh", "hetzner", "contabo", "leaseweb",
    "digitalocean", "vultr", "linode", "scaleway", "online.net",
    "ionos", "1&1", "strato", "plus.server", "gandi", "netcup",
    "cloudflare", "aiven", "fly.io", "railway", "vercel", "heroku",
    "azure", "microsoft", "amazon", "aws", "ec2", "compute",
    "google cloud", "gcp", "gce", "oracle cloud", "oci",
    "alibaba cloud", "aliyun", "tencent cloud", "huawei cloud",
    "bare metal", "cloud server", "cloud hosting",
    "colo cross", "xfinity", "comcast business",
    "m247", "psychz", "incero", "sharktech", "multacom",
    "quadranet", "porkbun", "hostwinds", "knownsrv",
]

# ============================================================
# 已知住宅 ISP 关键词
# 如果 ISP 包含这些词，较高概率是住宅 IP
# ============================================================
RESIDENTIAL_ISP_KEYWORDS = [
    "comcast", "charter", "spectrum", "cox", "verizon", "at&t", "centurylink",
    "frontier", "lumen", "telefonica", "deutsche telekom", "telecom italia",
    "orange", "bt", "virgin media", "sky uk", "talktalk",
    "kpn", "ziggo", "telenet", "proximus", "swisscom", "a1 telekom",
    "telia", "telenor", "telia", "elisa", "sonera",
    "singtel", "starhub", "m1", "tm net", "unifi", "true online",
    "chinanet", "chinaunicom", "china mobile", "cmcc", "cncgroup",
    "kddi", "softbank", "ntt", "ocn", "au one net", "so-net",
    "kt", "sk broadband", "lg u+", "kornet",
    "rogers", "bell canada", "shaw", "telus", "videotron",
    "optus", "telstra", "tpg", "aussie broadband", "iinet",
    "vodafone", "o2", "three", "ee", "plus.pl", "t-mobile",
]

# IP 类型枚举
IP_TYPE_RESIDENTIAL = "residential"
IP_TYPE_HOSTING = "hosting"
IP_TYPE_VPN = "vpn"
IP_TYPE_UNKNOWN = "unknown"


@dataclass
class IpPurityInfo:
    """IP 纯净度信息"""
    ip_address: str = ""
    asn: int = 0
    isp: str = ""
    org: str = ""
    country: str = ""
    ip_type: str = IP_TYPE_UNKNOWN  # residential / hosting / vpn / unknown
    is_datacenter: bool = False
    is_proxy: bool = False
    is_vpn: bool = False
    is_tor: bool = False
    fraud_score: float = -1.0  # -1 = 未检测, 0.0 = 纯净, 1.0 = 欺诈
    purity_score: float = 0.0  # 0.0 - 1.0, 越高越纯净
    source: str = ""  # 数据来源: ip-api / scamalytics / heuristic


@dataclass
class IpPurityResult:
    """节点 IP 纯净度检测结果"""
    proxy_name: str
    proxy_type: str
    server: str
    port: int
    purity_info: Optional[IpPurityInfo] = None
    query_success: bool = False


def _is_ip_in_cidr(ip_str: str, cidr_list: list) -> bool:
    """检查 IP 是否在已知的 CIDR 范围内"""
    try:
        ip = ipaddress.ip_address(ip_str)
        for cidr_str in cidr_list:
            network = ipaddress.ip_network(cidr_str, strict=False)
            if ip in network:
                return True
        return False
    except (ValueError, ipaddress.AddressValueError):
        return False


def _resolve_ip(server: str) -> Optional[str]:
    """解析域名到 IP 地址"""
    if not server:
        return None
    try:
        # 已经是 IP 地址
        ipaddress.ip_address(server)
        return server
    except ValueError:
        pass
    
    # 是域名，需要解析
    try:
        ip = socket.gethostbyname(server)
        return ip
    except (socket.gaierror, OSError) as e:
        logger.debug(f"DNS resolution failed for {server}: {e}")
        return None


def _query_ip_api(ip: str, retry: int = 2) -> Optional[dict]:
    """
    使用 ip-api.com 查询 IP 信息（免费，无 API Key 要求，45次/分钟）
    返回包含 asn, isp, org, country 等信息的字典
    """
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
                continue
            
            logger.debug(f"ip-api query failed for {ip}: {data.get('message', 'unknown')}")
            return None
            
        except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError) as e:
            if attempt < retry - 1:
                time.sleep(1)
                continue
            logger.debug(f"ip-api error for {ip}: {e}")
            return None
        except Exception as e:
            logger.debug(f"ip-api exception for {ip}: {e}")
            return None
    
    return None


def _check_scamalytics(ip: str) -> Optional[dict]:
    """
    使用 scamalytics.com 检查 IP 欺诈分数（免费，无需 API Key）
    注意：此方法可能不太稳定，返回的数据仅供参考
    """
    if not ip:
        return None
    
    try:
        url = f"https://scamalytics.com/ip/{ip}"
        req = urllib.request.Request(url=url)
        req.add_header("User-Agent", utils.USER_AGENT)
        
        resp = urllib.request.urlopen(req, timeout=15)
        html_content = resp.read().decode("utf-8", errors="replace")
        
        result = {}
        
        # 解析欺诈分数
        score_match = re.search(r'Fraud Score[^:]*:\s*(-?\d+)', html_content, re.IGNORECASE)
        if score_match:
            result["fraud_score"] = int(score_match.group(1))
        else:
            score_match = re.search(r'<div[^>]*class="score"[^>]*>\s*(-?\d+)\s*</div>', html_content, re.IGNORECASE)
            if score_match:
                result["fraud_score"] = int(score_match.group(1))
        
        # 解析风险等级
        risk_match = re.search(r'Risk\s*(Level|:)[^:]*:\s*(\w+)', html_content, re.IGNORECASE)
        if risk_match:
            result["risk"] = risk_match.group(2).strip().lower()
        
        # 解析 IP 类型
        type_match = re.search(r'IP\s*(Type|:)[^:]*:\s*(\w[\w\s]*)', html_content, re.IGNORECASE)
        if type_match:
            result["ip_type"] = type_match.group(2).strip().lower()
        
        # 解析 ASN 和组织信息
        asn_match = re.search(r'ASN[^:]*:\s*(\d+)', html_content, re.IGNORECASE)
        if asn_match:
            result["asn"] = int(asn_match.group(1))
        
        org_match = re.search(r'(?:ISP|Organization)[^:]*:\s*([^\n<]+)', html_content, re.IGNORECASE)
        if org_match:
            result["org"] = org_match.group(1).strip()
        
        return result if result else None
        
    except Exception as e:
        logger.debug(f"scamalytics check failed for {ip}: {e}")
        return None


def _classify_ip_type(isp: str = "", org: str = "", asn: int = 0) -> str:
    """
    根据 ISP/ORG/ASN 判断 IP 类型
    返回 residential / hosting / unknown
    """
    text = f"{isp} {org}".lower()
    
    # 检查住宅 ISP 关键词（高优先级）
    for kw in RESIDENTIAL_ISP_KEYWORDS:
        if kw in text:
            return IP_TYPE_RESIDENTIAL
    
    # 检查机房关键词
    for kw in HOSTING_KEYWORDS:
        if kw in text:
            return IP_TYPE_HOSTING
    
    # 检查已知机房 ASN
    if asn > 0 and asn in KNOWN_DATACENTER_ASNS:
        return IP_TYPE_HOSTING
    
    return IP_TYPE_UNKNOWN


def _compute_purity_score(
    ip_type: str,
    is_datacenter: bool,
    is_proxy: bool,
    is_vpn: bool,
    is_tor: bool,
    fraud_score: float,
    is_in_known_cidr: bool,
) -> float:
    """
    计算 IP 纯净度综合得分 (0.0 - 1.0)
    1.0 = 极其纯净（真实住宅 IP，无任何不良标记）
    0.0 = 完全不纯净（机房/代理/VPN IP）
    
    扣分规则:
    - 机房 IP (hosting/datacenter): -0.60
    - VPN/代理: -0.80
    - Tor 出口: -0.90
    - 已知机房 CIDR: -0.50
    - ip-api proxy=true: -0.40
    - ip-api hosting=true: -0.30
    - 欺诈分数每 10分: -0.05（最高 -0.40）
    """
    score = 1.0
    
    # IP 类型判断
    if ip_type == IP_TYPE_HOSTING:
        score -= 0.60
    elif ip_type == IP_TYPE_VPN:
        score -= 0.80
    
    # 已知 CIDR 范围
    if is_in_known_cidr:
        score -= 0.50
    
    # ip-api 标记
    if is_datacenter:
        score -= 0.30
    if is_proxy:
        score -= 0.40
    if is_vpn:
        score -= 0.40
    if is_tor:
        score -= 0.90
    
    # 欺诈分数扣分
    if fraud_score > 0:
        penalty = min(0.40, fraud_score * 0.005)  # 100分扣0.50，但上限0.40
        score -= penalty
    
    return max(0.05, min(1.0, score))


def check_ip_purity(
    proxy: dict,
    use_scamalytics: bool = False,
    retry: int = 2,
) -> IpPurityResult:
    """
    对单个代理节点进行 IP 纯净度检测
    
    检测流程:
    1. 解析域名获取 IP 地址
    2. 检查是否在已知机房 CIDR 范围内
    3. 通过 ip-api.com 查询 ASN/ISP/ORG
    4. 通过 ASN/ISP/ORG 关键词判断 IP 类型
    5. 可选：通过 scamalytics 查询欺诈分数
    6. 综合计算纯净度得分
    
    返回 IpPurityResult
    """
    if not proxy or not isinstance(proxy, dict):
        return IpPurityResult(
            proxy_name=proxy.get("name", "") if proxy else "",
            proxy_type="",
            server="",
            port=0,
            query_success=False,
        )
    
    proxy_name = proxy.get("name", "")
    proxy_type = proxy.get("type", "")
    server = proxy.get("server", "")
    port = int(proxy.get("port", 0))
    
    result = IpPurityResult(
        proxy_name=proxy_name,
        proxy_type=proxy_type,
        server=server,
        port=port,
    )
    
    # 1. 解析 IP
    ip = _resolve_ip(server)
    if not ip:
        logger.debug(f"cannot resolve IP for proxy {proxy_name}, server={server}")
        result.query_success = False
        return result
    
    purity = IpPurityInfo(ip_address=ip)
    
    # 2. 检查已知 CIDR
    purity.is_datacenter = _is_ip_in_cidr(ip, KNOWN_DATACENTER_CIDRS)
    is_in_known_cidr = purity.is_datacenter
    
    # 3. 查询 ip-api
    ip_api_data = _query_ip_api(ip, retry=retry)
    
    if ip_api_data:
        # 解析 ASN
        as_str = ip_api_data.get("as", "")
        asn_match = re.search(r'AS(\d+)', str(as_str), re.IGNORECASE)
        if asn_match:
            purity.asn = int(asn_match.group(1))
        
        purity.isp = ip_api_data.get("isp", "")
        purity.org = ip_api_data.get("org", "")
        purity.country = ip_api_data.get("country", "")
        
        # ip-api 的 proxy/hosting 标记
        if ip_api_data.get("proxy", False):
            purity.is_proxy = True
        if ip_api_data.get("hosting", False):
            purity.is_datacenter = True
        
        # 检查是否在已知机房 ASN 列表
        if purity.asn > 0 and purity.asn in KNOWN_DATACENTER_ASNS:
            purity.is_datacenter = True
        
        # 根据 ISP/ORG 分类 IP 类型
        purity.ip_type = _classify_ip_type(
            isp=purity.isp,
            org=purity.org,
            asn=purity.asn,
        )
        
        # 覆盖 ip_type：如果 ip-api 标记了 hosting 或 proxy
        if purity.is_proxy:
            purity.ip_type = IP_TYPE_VPN
        elif purity.is_datacenter and purity.ip_type == IP_TYPE_UNKNOWN:
            purity.ip_type = IP_TYPE_HOSTING
        
        purity.source = "ip-api"
    
    else:
        # ip-api 查询失败，使用启发式判断
        purity.ip_type = _classify_ip_type(
            isp=server,  # 使用域名作为 isp 参考
            org="",
            asn=0,
        )
        if is_in_known_cidr:
            purity.ip_type = IP_TYPE_HOSTING
            purity.is_datacenter = True
        
        purity.source = "heuristic"
    
    # 4. 可选：查询 scamalytics 欺诈分数
    if use_scamalytics:
        scam_data = _check_scamalytics(ip)
        if scam_data:
            purity.fraud_score = float(scam_data.get("fraud_score", -1))
            if "risk" in scam_data:
                purity.is_vpn = purity.is_vpn or ("vpn" in scam_data.get("risk", "").lower())
                purity.is_proxy = purity.is_proxy or ("proxy" in scam_data.get("risk", "").lower())
            if "ip_type" in scam_data:
                ip_type_text = scam_data["ip_type"].lower()
                if "hosting" in ip_type_text or "datacenter" in ip_type_text:
                    purity.is_datacenter = True
                    if purity.ip_type == IP_TYPE_UNKNOWN:
                        purity.ip_type = IP_TYPE_HOSTING
                if "vpn" in ip_type_text or "proxy" in ip_type_text:
                    purity.is_proxy = True
                    purity.is_vpn = True
                    purity.ip_type = IP_TYPE_VPN
            
            if purity.source == "heuristic":
                purity.source = "scamalytics"
            else:
                purity.source += "+scamalytics"
    
    # 5. 计算纯净度得分
    purity.purity_score = _compute_purity_score(
        ip_type=purity.ip_type,
        is_datacenter=purity.is_datacenter,
        is_proxy=purity.is_proxy,
        is_vpn=purity.is_vpn,
        is_tor=purity.is_tor,
        fraud_score=purity.fraud_score,
        is_in_known_cidr=is_in_known_cidr,
    )
    
    result.purity_info = purity
    result.query_success = True
    
    return result


def batch_check_ip_purity(
    proxies: list,
    use_scamalytics: bool = False,
    retry: int = 2,
    num_threads: int = 16,
    show_progress: bool = False,
) -> dict[str, IpPurityResult]:
    """
    批量检测代理节点的 IP 纯净度
    
    返回: {proxy_name: IpPurityResult}
    """
    if not proxies:
        return {}
    
    params = [
        [p, use_scamalytics, retry]
        for p in proxies
        if isinstance(p, dict) and p.get("name", "") and p.get("server", "")
    ]
    
    if not params:
        return {}
    
    logger.info(
        f"starting IP purity check for {len(params)} proxies..."
    )
    
    results_list = utils.multi_thread_run(
        func=check_ip_purity,
        tasks=params,
        num_threads=num_threads,
        show_progress=show_progress,
    )
    
    purity_map = {}
    for r in results_list:
        if r and isinstance(r, IpPurityResult) and r.proxy_name:
            purity_map[r.proxy_name] = r
    
    # 统计
    residential = sum(1 for r in purity_map.values() if r.purity_info and r.purity_info.ip_type == IP_TYPE_RESIDENTIAL)
    hosting = sum(1 for r in purity_map.values() if r.purity_info and r.purity_info.ip_type == IP_TYPE_HOSTING)
    unknown = sum(1 for r in purity_map.values() if r.purity_info and r.purity_info.ip_type == IP_TYPE_UNKNOWN)
    vpn = sum(1 for r in purity_map.values() if r.purity_info and r.purity_info.ip_type == IP_TYPE_VPN)
    
    logger.info(
        f"IP purity check finished: total={len(purity_map)}, "
        f"residential={residential}, hosting={hosting}, "
        f"vpn/proxy={vpn}, unknown={unknown}"
    )
    
    return purity_map


def optimize_by_purity(
    proxies: list,
    purity_map: dict[str, IpPurityResult],
    drop_hosting: bool = False,
    drop_vpn: bool = True,
    purity_threshold: float = 0.0,
    top_ratio: float = 1.0,
) -> list:
    """
    根据 IP 纯净度对代理进行优选排序
    
    参数:
        proxies: 代理列表
        purity_map: IP 纯净度检测结果
        drop_hosting: 是否丢弃机房 IP
        drop_vpn: 是否丢弃 VPN/代理 IP
        purity_threshold: 最低纯净度阈值，低于此值丢弃
        top_ratio: 保留排名前多少比例 (0.0 - 1.0)
    
    返回: 按纯净度排序后的代理列表
    """
    if not proxies or not purity_map:
        return proxies or []
    
    scored = []
    for p in proxies:
        name = p.get("name", "")
        result = purity_map.get(name)
        
        if not result or not result.query_success or not result.purity_info:
            # 没有检测结果，放最后
            scored.append((p, 0.0, IP_TYPE_UNKNOWN))
            continue
        
        purity = result.purity_info
        
        # 丢弃策略
        if drop_hosting and purity.ip_type == IP_TYPE_HOSTING:
            logger.debug(f"drop hosting IP proxy: {name}, isp={purity.isp}, asn={purity.asn}")
            continue
        
        if drop_vpn and purity.ip_type == IP_TYPE_VPN:
            logger.debug(f"drop VPN/proxy IP proxy: {name}, isp={purity.isp}")
            continue
        
        # 纯净度阈值过滤
        if purity.purity_score < purity_threshold:
            logger.debug(
                f"drop low purity proxy: {name}, "
                f"score={purity.purity_score:.4f}, type={purity.ip_type}"
            )
            continue
        
        scored.append((p, purity.purity_score, purity.ip_type))
    
    # 按纯净度降序排列
    scored.sort(key=lambda x: (x[1], x[0].get("name", "")), reverse=True)
    
    # 可选只保留前 top_ratio 比例
    if top_ratio < 1.0 and scored:
        keep_count = max(1, int(len(scored) * top_ratio))
        scored = scored[:keep_count]
        logger.info(f"top {top_ratio:.0%} selection: keep {keep_count}")
    
    ordered = [item[0] for item in scored]
    
    # 在节点名上附加类型标记
    name_map = {}
    for p, score, ip_type in scored:
        name = p.get("name", "")
        if name:
            tag = ""
            if ip_type == IP_TYPE_RESIDENTIAL:
                tag = "🏠"
            elif ip_type == IP_TYPE_HOSTING:
                tag = "🏢"
            elif ip_type == IP_TYPE_VPN:
                tag = "🔒"
            else:
                tag = "❓"
            
            # 标记纯净度星级
            stars = ""
            if score >= 0.8:
                stars = "⭐⭐⭐⭐⭐"
            elif score >= 0.6:
                stars = "⭐⭐⭐⭐"
            elif score >= 0.4:
                stars = "⭐⭐⭐"
            elif score >= 0.2:
                stars = "⭐⭐"
            else:
                stars = "⭐"
            
            name_map[name] = f"{name} {tag}{stars}"
    
    # 更新节点名
    for p in ordered:
        name = p.get("name", "")
        if name in name_map:
            p["name"] = name_map[name]
    
    dropped = len(proxies) - len(ordered)
    if dropped > 0:
        logger.info(f"purity optimization: keep {len(ordered)}, dropped {dropped} proxies")
    
    return ordered


@dataclass
class PurityConfig:
    """IP 纯净度检测配置"""
    enabled: bool = False
    use_scamalytics: bool = False  # 是否使用 scamalytics（较慢但更准确）
    retry: int = 2
    drop_hosting: bool = False  # 是否丢弃机房 IP
    drop_vpn: bool = True  # 是否丢弃 VPN/代理 IP
    purity_threshold: float = 0.0  # 最低纯净度（0.0-1.0）
    top_ratio: float = 1.0  # 保留前 N% 纯净节点
    inject_tags: bool = True  # 是否在节点名上添加类型标记
    
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
        )


def load_purity_config_from_env() -> PurityConfig:
    """从环境变量加载 IP 纯净度配置"""
    enabled = os.environ.get("PURITY_ENABLED", "").lower() in ["true", "1"]
    if not enabled:
        return PurityConfig(enabled=False)
    
    config = PurityConfig(enabled=True)
    try:
        config.use_scamalytics = os.environ.get("PURITY_USE_SCAMALYTICS", "").lower() in ["true", "1"]
        retry = os.environ.get("PURITY_RETRY", "")
        if retry:
            config.retry = max(1, int(retry))
        config.drop_hosting = os.environ.get("PURITY_DROP_HOSTING", "").lower() in ["true", "1"]
        config.drop_vpn = os.environ.get("PURITY_DROP_VPN", "true").lower() not in ["false", "0"]
        threshold = os.environ.get("PURITY_THRESHOLD", "")
        if threshold:
            config.purity_threshold = min(1.0, max(0.0, float(threshold)))
        top_ratio = os.environ.get("PURITY_TOP_RATIO", "")
        if top_ratio:
            config.top_ratio = min(1.0, max(0.01, float(top_ratio)))
        config.inject_tags = os.environ.get("PURITY_INJECT_TAGS", "true").lower() not in ["false", "0"]
    except (ValueError, TypeError) as e:
        logger.warning(f"failed to parse purity config from env: {e}")
    
    return config
