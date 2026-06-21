# -*- coding: utf-8 -*-
"""LangChain 模型工厂 - 统一构造目标模型与判定模型

集中封装 LangChain ChatOpenAI 的构造逻辑,替代原先散落在 agent.py / gui_app.py
中的手写 requests HTTP 调用。OpenAI 兼容端点(base_url)由调用方传入,LangChain
原生支持 max_retries 内置退避重试,因此不再需要手写 for attempt 循环。
"""
from langchain_openai import ChatOpenAI

# OpenAI 兼容服务在无 key 时通常不校验,传一个占位符避免 SDK 报缺 key
_EMPTY_KEY = "EMPTY"


def build_target_llm(base_url, api_key, model_name, temperature=0.7,
                     max_tokens=500, timeout=30, retries=2):
    """构造被测目标模型(红队攻击对象)。

    参数与原 RedTeamAgent 的取值一一对应:
      base_url      OpenAI 兼容端点,如 http://localhost:8045/v1
      api_key       Bearer Token,空字符串时用占位符
      model_name    模型 id
      temperature   采样温度(评测默认 0.7)
      max_tokens    单次回复上限
      timeout       单次请求超时(秒)
      retries       失败重试次数(LangChain 内置指数退避)
    """
    return ChatOpenAI(
        base_url=base_url.rstrip("/") if base_url else None,
        api_key=api_key or _EMPTY_KEY,
        model=model_name,
        temperature=temperature,
        max_tokens=max_tokens,
        timeout=timeout,
        max_retries=retries,
    )


def build_judge_llm(base_url, api_key, model_name, temperature=0.3,
                    max_tokens=300, timeout=30, retries=2):
    """构造 AI 判定模型(用于 LLM-as-Judge 评估目标模型响应)。

    判定模型与目标模型相互独立,可用更强模型评判弱模型。
    温度更低(0.3)以保证判定稳定。
    """
    return ChatOpenAI(
        base_url=base_url.rstrip("/") if base_url else None,
        api_key=api_key or _EMPTY_KEY,
        model=model_name,
        temperature=temperature,
        max_tokens=max_tokens,
        timeout=timeout,
        max_retries=retries,
    )
