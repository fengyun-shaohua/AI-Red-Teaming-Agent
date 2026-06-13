# AI Red Teaming Agent — 大模型红队安全评测工具

基于 Python/tkinter 的 GUI 红队测试工具，用于评估大语言模型的内容安全防线能力。

## 功能特点

- **多模板测试**：内置 7 种测试模板，涵盖角色扮演、Prompt Injection、编码绕过、多轮对话、网安研究等手法
- **Agent 智能分析**：可选的 AI Agent 自动判定，替代人工审核
- **数据库持久化**：SQLite 自动保存模板、载荷、测试结果，重启不丢失
- **专业报告导出**：HTML 红队评测报告，含统计卡片、绕过率/拦截率分析
- **模型管理**：支持获取模型列表、弹窗选择模型

## 快速开始

```bash
# 安装依赖
pip install requests

# 启动 GUI
python gui_app.py

# 或使用 CLI 版本
python red_team_cli.py
```

## 使用说明

1. 在「API 配置」区填写目标模型的 Base URL 和 API Key
2. 点击「获取模型」拉取可用模型列表，点击 `...` 弹窗选择
3. 在「测试模板」和「测试载荷」Tab 勾选要使用的项目
4. 可选：配置「Agent 智能分析」输入分析模型的 API/Key/Model 进行自动判定
5. 点击「开始测试」执行
6. 测试完成后可导出 HTML/JSON 报告

## 项目结构

```
agent红队测试/
├── gui_app.py              # 主 GUI 程序
├── red_team_cli.py          # CLI 入口
├── red_team_core/           # 核心模块
│   ├── __init__.py
│   ├── agent.py             # 测试执行引擎
│   ├── analyzer.py          # 响应分析器
│   ├── reporter.py          # 报告生成器
│   ├── templates.py         # 测试模板库
│   └── db.py                # SQLite 持久化
├── .gitignore
└── README.md
```

## 免责声明

本工具仅用于大语言模型的安全研究和防御体系建设。请勿将其用于非法用途。