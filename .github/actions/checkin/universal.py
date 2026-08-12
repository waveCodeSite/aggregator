#!/usr/bin/env python
# -*- coding: utf-8 -*-

# @Author  : wzdnzd
# @Time    : 2018-04-25

import re
import warnings
import urllib
import urllib.request
import urllib.parse
import multiprocessing
import os
import ssl
import json

warnings.filterwarnings("ignore")

HEADER = {
    "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.5060.53 Safari/537.36 Edg/103.0.1264.37",
    "accept": "application/json, text/javascript, */*; q=0.01",
    "accept-language": "zh-CN,zh;q=0.9",
    "dnt": "1",
    "Connection": "keep-alive",
    "content-type": "application/x-www-form-urlencoded; charset=UTF-8",
    "x-requested-with": "XMLHttpRequest",
}

CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE

PATH = os.path.abspath(os.path.dirname(__file__))


def extract_domain(url) -> str:
    if not url or not re.match(
        "^(https?:\/\/(([a-zA-Z0-9]+-?)+\.)+[a-zA-Z]+)(:\d+)?(\/.*)?(\?.*)?(#.*)?$", url
    ):
        return ""

    start = url.find("//")
    if start == -1:
        start = -2

    end = url.find("/", start + 2)
    if end == -1:
        end = len(url)

    return url[:end]


def login(url, params, headers, retry, jsonify=False) -> str:
    try:
        if jsonify:
            headers["content-type"] = "application/json"
            data = json.dumps(params).encode(encoding="UTF8")
        else:
            headers["content-type"] = "application/x-www-form-urlencoded; charset=UTF-8"
            data = urllib.parse.urlencode(params).encode(encoding="UTF8")

        request = urllib.request.Request(url, data=data, headers=headers, method="POST")

        response = urllib.request.urlopen(request, timeout=10, context=CTX)
        print(response.read().decode("unicode_escape"))

        if response.getcode() == 200:
            return response.getheader("Set-Cookie")

        return ""

    except Exception as e:
        print(str(e))
        retry -= 1

        if retry > 0:
            return login(url, params, headers, retry, jsonify)

        print("[LoginError] URL: {}".format(extract_domain(url)))
        return ""


def checkin(url, headers, retry) -> None:
    try:
        request = urllib.request.Request(url, headers=headers, method="POST")

        response = urllib.request.urlopen(request, timeout=10, context=CTX)
        data = response.read().decode("unicode_escape")
        print(
            "[CheckInFinished] URL: {}\t\tResult:{}".format(extract_domain(url), data)
        )

    except Exception as e:
        print(str(e))
        retry -= 1

        if retry > 0:
            checkin(url, headers, retry)

        print("[CheckInError] URL: {}".format(extract_domain(url)))


def get_cookie(text) -> str:
    regex = "(__cfduid|uid|email|key|ip|expire_in)=(.+?);"
    if not text:
        return ""

    content = re.findall(regex, text)
    cookie = ";".join(["=".join(x) for x in content]).strip()

    return cookie


def config_load(filename) -> dict:
    if not os.path.exists(filename) or os.path.isdir(filename):
        return None

    config = open(filename, "r").read()
    return json.loads(config)


def load_accounts_from_gist() -> list:
    """从私有 Gist 读取 Collect 自动注册并持久化的账号列表"""
    token = os.environ.get("GIST_PAT", "")
    link = os.environ.get("GIST_LINK", "")
    if not token or not link:
        print("[LoadAccountsError] environment GIST_PAT or GIST_LINK is empty, fallback to local config")
        return []

    words = str(link).strip().split("/", maxsplit=1)
    if len(words) != 2 or not words[0].strip() or not words[1].strip():
        print("[LoadAccountsError] invalid GIST_LINK, should be 'username/gist_id' format")
        return []

    username, gist_id = words[0].strip(), words[1].strip()
    url = "https://gist.githubusercontent.com/{}/{}/raw/accounts.json".format(username, gist_id)
    headers = {"Authorization": "Bearer {}".format(token), "User-Agent": HEADER.get("user-agent", "")}

    try:
        request = urllib.request.Request(url, headers=headers)
        response = urllib.request.urlopen(request, timeout=30, context=CTX)
        if response.getcode() != 200:
            print("[LoadAccountsError] cannot load accounts from gist, code: {}".format(response.getcode()))
            return []

        data = json.loads(response.read().decode("UTF8"))
    except Exception as e:
        print("[LoadAccountsError] cannot load accounts from gist: {}".format(str(e)))
        return []

    if not isinstance(data, dict):
        return []

    domains = []
    for domain, acc in data.items():
        if not acc or not isinstance(acc, dict):
            continue

        email, passwd = acc.get("email", ""), acc.get("passwd", "")
        if not email or not passwd:
            continue

        domains.append(
            {
                "domain": domain,
                "param": {
                    "email": email,
                    "passwd": passwd,
                    "login": acc.get("login", "/auth/login"),
                    "checkin": acc.get("checkin", "/user/checkin"),
                    "jsonify": acc.get("jsonify", False),
                    "sub": acc.get("sub", ""),
                },
            }
        )

    return domains


def check_sub_valid(url: str) -> bool:
    """签到前检查订阅是否仍有效；无订阅链接视为有效（兼容手动配置）"""
    if not url:
        return True

    try:
        request = urllib.request.Request(
            url, headers={"User-Agent": "{}; Clash.Meta; Mihomo; Shadowrocket;".format(HEADER.get("user-agent", ""))}
        )
        response = urllib.request.urlopen(request, timeout=10, context=CTX)
        if response.getcode() != 200:
            return False

        # 内容过短视为失效（防止命中错误页面）
        content = response.read(1024 * 1024)
        return len(content) >= 32
    except Exception as e:
        print("[CheckSubError] URL: {}	Error: {}".format(extract_domain(url), str(e)))
        return False


def flow(domain, params, headers) -> bool:
    domain = extract_domain(domain.strip())
    if not domain:
        print("cannot checkin because domain is invalidate")
        return False

    print("start to checkin, domain: {}".format(domain))
    login_url = domain + params.get("login", "/auth/login")
    checkin_url = domain + params.get("checkin", "/user/checkin")
    headers["origin"] = domain
    headers["referer"] = login_url

    user_info = {"email": params.get("email", ""), "passwd": params.get("passwd", "")}

    jsonify = params.get("jsonify", False)
    text = login(login_url, user_info, headers, 3, jsonify)
    if not text:
        return False

    cookie = get_cookie(text)
    if len(cookie) <= 0:
        return False

    headers["referer"] = domain + "/user"
    headers["cookie"] = cookie

    checkin(checkin_url, headers, 3)
    return True


def wrapper(args) -> bool:
    param = args.get("param", {}) if isinstance(args, dict) else {}
    sub = param.get("sub", "") if isinstance(param, dict) else ""

    # 订阅已失效的账号直接跳过，减少无效签到请求
    if not check_sub_valid(sub):
        print("[SkipCheckin] subscription is invalid, domain: {}".format(args.get("domain", "") if isinstance(args, dict) else ""))
        return False

    return flow(args.get("domain", ""), param, HEADER)


def main() -> None:
    # 优先读取 Gist 上持久化的账号（Collect 自动注册），失败则回退本地 config.json
    params = load_accounts_from_gist()
    if not params:
        config = config_load(os.path.join(PATH, "config.json"))
        params = config.get("domains", []) if config else []

    if not params:
        print("[CheckinError] cannot found any valid account, exit")
        return

    cpu_count = multiprocessing.cpu_count()
    num = len(params) if len(params) <= cpu_count else cpu_count

    pool = multiprocessing.Pool(num)
    pool.map(wrapper, params)
    pool.close()


if __name__ == "__main__":
    main()
