# CVE威胁情报推送系统

## 📋 项目简介

该项目用于监控多个安全平台的最新威胁情报信息，并通过多种渠道（钉钉、飞书、Telegram等）进行实时推送。

系统融合了以下多个数据源的威胁情报信息：
- OSCS1024漏洞库
- 安天威胁情报
- Tenable平台
- 微软安全中心
- CVE平台

## ✨ 功能特性

- **🔄 多平台监控**：同时监控多个漏洞平台的最新CVE信息
- **📢 多渠道推送**：支持钉钉、飞书、Telegram Bot等多种推送渠道
- **📋 日报生成**：自动生成每日漏洞日报，支持Markdown和HTML格式
- **🌐 Web界面**：生成静态HTML页面，可部署到GitHub Pages
- **📡 RSS支持**：生成WordPress兼容的RSS feed
- **🔍 去重处理**：使用SQLite数据库存储已推送的漏洞信息，避免重复推送
- **🛡️ 健壮性优化**：增强了异常处理、资源管理、中断处理等功能
- **⚙️ 灵活配置**：通过YAML配置文件可以灵活定制推送渠道和系统参数
- **📈 GitHub API优化**：支持GitHub token认证，解决速率限制问题

## 📦 安装依赖

```bash
pip install -r requirements.txt
```

## ⚙️ 配置说明

在`config.yaml`文件中配置推送渠道和相关参数：

```yaml
all_config:
 dingding:
   - enable: 1  # 1启用, 0禁用
   - webhook: https://oapi.dingtalk.com/robot/send?access_token=
   - secretKey: 
   - app_name: dingding
 feishu:
   - enable: 0  # 1启用, 0禁用
   - webhook: xxx
   - app_name: feishu
 tgbot:
   - enable: 0  # 1启用, 0禁用
   - token: 123
   - group_id: 123
   - app_name: tgbot
 translate:
   - enable: 1
   - provider: google
   - api_key: ""  # 如果使用googletrans库则不需要填写
   - source_lang: auto
   - target_lang: zh-cn
 run_config:
   - enable_night_sleep: 1  # 启用夜间休眠
   - night_sleep_start: 0  # 休眠开始时间（小时）
   - night_sleep_end: 7  # 休眠结束时间（小时）
   - check_interval: 7200  # 检查间隔，单位：秒，默认2小时
   - max_run_time: 3540  # 最大运行时间，单位：秒，默认59分钟
   - exception_retry_interval: 60  # 异常重试间隔，单位：秒，默认1分钟
   - github_token: ""  # GitHub API令牌，用于解决速率限制问题
```

## 🚀 使用方法

### 直接运行

```bash
python CVE_monitor.py
```

### 单次执行模式

```bash
python CVE_monitor.py --once
```

### 生成日报模式

```bash
python CVE_monitor.py --daily-report
```

### 关闭推送模式

```bash
python CVE_monitor.py --no-push
```

## 📁 目录结构

```
.
├── CVE_monitor.py       # 主程序
├── config.yaml          # 配置文件
├── data.db              # SQLite数据库
├── requirements.txt     # 依赖列表
├── log/                 # 日志目录
│   ├── run.log          # 运行日志
│   └── err.log          # 错误日志
├── archive/             # 日报存档
│   └── YYYY-MM-DD/      # 按日期存档
├── static/              # 静态文件
│   ├── index.html       # 日报索引页面
│   └── template.html    # HTML模板
└── RSS/                 # RSS目录
    └── cve_rss.xml      # WordPress兼容RSS feed
```

## 📊 日志说明

系统日志存放在`log`目录下：
- `run.log`：运行日志，记录程序运行状态
- `err.log`：错误日志，记录程序异常信息

日志文件会按天进行切割，并保留最近7天的日志记录。

## 🔄 GitHub Actions

项目包含GitHub Actions工作流配置，支持：
- 定时运行（北京时间9点）
- 手动触发运行
- 自动提交更新到仓库

## 📝 注意事项

1. 确保配置文件中至少启用了一个推送渠道
2. 程序设计为长时间运行，支持优雅退出（Ctrl+C）
3. 如需修改抓取频率，请在配置文件的`run_config`部分调整`check_interval`参数
4. 建议配置GitHub token以提高API请求速率限制

## 🤝 贡献

欢迎提交Issue和Pull Request，共同改进项目！

## 📄 许可证

MIT License