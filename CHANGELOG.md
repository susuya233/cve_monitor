# 📋 更新日志

## 🎉 v2.0.0 (2025-12-16)

### ✨ 新功能

- **📋 日报生成**：自动生成每日漏洞日报，支持Markdown和HTML格式
- **🌐 Web界面**：生成静态HTML页面，可部署到GitHub Pages
- **📡 RSS支持**：生成WordPress兼容的RSS feed
- **📦 目录结构优化**：
  - `archive/YYYY-MM-DD/`：存储每日日报
  - `static/`：存储静态HTML文件
  - `RSS/`：存储RSS feed文件

### 🛠️ 优化改进

- **📈 GitHub API优化**：支持GitHub token认证，解决速率限制问题
- **📁 配置文件优化**：移除了未使用的`server`和`pushplus`推送配置
- **🔧 deploy.sh优化**：简化日志处理，使用程序内部日志机制
- **📝 README更新**：添加了emojis，更新了配置说明和使用方法
- **🚀 GitHub Actions优化**：添加GITHUB_TOKEN环境变量配置
- **🎨 模板优化**：HTML模板优化，字体大小调整，链接在新标签页打开

### 🐛 Bug修复

- **📝 日志编码问题**：修复了日志的UnicodeEncodeError问题
- **📁 目录创建问题**：确保所有需要的目录都能正确创建
- **🔧 配置加载问题**：修复了配置文件加载的异常处理

### 📚 文档更新

- **📖 详细的README**：添加了功能特性、配置说明、使用方法等
- **📋 更新日志**：创建了CHANGELOG.md文件，记录版本更新历史

### 🚀 部署优化

- **🌐 支持GitHub Pages**：生成的静态文件可直接部署
- **🔄 自动提交**：GitHub Actions自动提交更新到仓库
- **⏰ 定时运行**：北京时间9点自动运行

## 📝 升级说明

1. 确保已安装所有依赖：`pip install -r requirements.txt`
2. 更新配置文件`config.yaml`，移除了`server`和`pushplus`配置
3. 配置GitHub token以提高API请求速率限制
4. 可以通过环境变量或配置文件设置GitHub token

## 🤝 贡献

欢迎提交