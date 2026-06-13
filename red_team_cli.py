"""CLI入口 - 大模型红队评测"""
import argparse, glob, os, sys
from datetime import datetime
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from red_team_core import JAILBREAK_TEMPLATES, DEFAULT_PAYLOADS, load_payloads
from red_team_core import RedTeamAgent

def main():
    parser = argparse.ArgumentParser(description="大模型红队评测 CLI")
    
    parser.add_argument("--api-key", help="API Key")
    parser.add_argument("--base-url", default="https://api.openai.com/v1", help="API 地址")
    parser.add_argument("--model", default="gpt-3.5-turbo", help="模型名称")
    parser.add_argument("--concurrency", type=int, default=5, help="并发数(默认5)")
    parser.add_argument("--retries", type=int, default=2, help="重试次数(默认2)")
    parser.add_argument("--timeout", type=int, default=30, help="超时秒数(默认30)")
    parser.add_argument("--payloads", default=None, help="自定义载荷JSON文件")
    parser.add_argument("--output", default="red_team_report.html", help="报告文件名")
    args = parser.parse_args()

    payloads = load_payloads(args.payloads) if args.payloads else DEFAULT_PAYLOADS

    agent = RedTeamAgent(api_key=args.api_key, base_url=args.base_url, model_name=args.model,
                         concurrency=args.concurrency, retries=args.retries, timeout=args.timeout)
    agent.run_evaluation(payloads=payloads)
    agent.generate_report(output_file=args.output)


if __name__ == "__main__":
    main()