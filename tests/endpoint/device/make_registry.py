# ruff: noqa: E501
"""기준 단말(pj1)에서 실행: 승인할 로컬 서버의 실행 계약을 읽어 승인 계약 파일(registry.json)을 만든다.

훅이 쓰는 함수(declared_contract)를 그대로 불러 같은 계산으로 만든다. 표준 라이브러리만 쓴다.
사용: python3 make_registry.py --hook <hook.py> --mcp-config <MCP 설정 JSON> --name cnt \
        --server-id srv-local-cnt --standin-url https://standin.invalid/mcp [--name ... 반복 불가]
작업 디렉터리는 하네스가 세션 디렉터리에서 서버를 띄우므로 승인본에서 비운다.
"""

import argparse
import importlib.util
import json
import sys


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--hook", required=True)
    parser.add_argument("--mcp-config", required=True)
    parser.add_argument("--name", required=True)
    parser.add_argument("--server-id", required=True)
    parser.add_argument("--standin-url", required=True)
    args = parser.parse_args(argv)
    spec = importlib.util.spec_from_file_location("mint_hook", args.hook)
    hook = importlib.util.module_from_spec(spec)
    sys.modules["mint_hook"] = hook
    spec.loader.exec_module(hook)
    with open(args.mcp_config, encoding="utf-8") as handle:
        config = json.load(handle)
    contract = hook.declared_contract(args.name, config, "/")
    contract["cwd"] = None
    entry = {
        "name": args.name,
        "server_id": args.server_id,
        "standin_url": args.standin_url,
        "transport": "http",
        "contract": contract,
    }
    print(json.dumps({"servers": [entry]}, indent=1))


if __name__ == "__main__":
    main()
