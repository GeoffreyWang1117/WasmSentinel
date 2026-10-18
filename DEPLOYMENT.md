# 🚀 GitHub Pages 自动部署说明

## 📋 部署步骤

### 1. 启用 GitHub Pages

1. 进入您的 GitHub 仓库设置页面
2. 滚动到 "Pages" 部分
3. 在 "Source" 下拉菜单中选择 "GitHub Actions"
4. 点击 "Save" 保存设置

### 2. 配置仓库权限

确保 GitHub Actions 有足够的权限：

1. 进入 Settings → Actions → General
2. 在 "Workflow permissions" 部分选择 "Read and write permissions"
3. 勾选 "Allow GitHub Actions to create and approve pull requests"
4. 点击 "Save" 保存

### 3. 更新部署配置

编辑 `.github/workflows/deploy-demo.yml` 文件，将以下内容中的 `your-username` 替换为您的 GitHub 用户名：

```yaml
# 第 62 行附近
<loc>https://your-username.github.io/WasmSentinel/</loc>
```

### 4. 更新演示网站链接

更新以下文件中的链接：

**demo-website/index.html**：
```html
<!-- 第 105 行附近 -->
<li class="nav-item"><a class="nav-link" href="https://github.com/your-username/WasmSentinel" target="_blank"><i class="fab fa-github"></i> GitHub</a></li>
```

**README.md**：
```markdown
**🌐 [访问演示网站](https://your-username.github.io/WasmSentinel/)**
```

### 5. 触发部署

提交并推送您的更改：

```bash
git add .
git commit -m "🚀 Add demo website and GitHub Pages deployment"
git push origin main
```

## 📖 自动部署流程

### 触发条件
- 推送到 `main` 或 `master` 分支
- 修改 `demo-website/` 目录内容
- 修改 `README.md` 或 `TEST_REPORT.md`
- 手动触发 (workflow_dispatch)

### 构建过程
1. **检出代码**：下载仓库内容
2. **设置 Pages**：配置 GitHub Pages 环境
3. **复制演示网站**：将 `demo-website/` 内容复制到 `_site/`
4. **复制文档**：将 README 和测试报告复制到 `_site/docs/`
5. **生成 API 文档**：自动创建 API 接口说明页面
6. **生成站点地图**：创建 sitemap.xml 用于 SEO
7. **上传构建产物**：准备部署内容
8. **部署到 Pages**：发布到 GitHub Pages

### 部署结果
部署成功后，您的演示网站将在以下地址可用：
- **主页**: https://your-username.github.io/WasmSentinel/
- **文档**: https://your-username.github.io/WasmSentinel/docs/quickstart.html
- **API 文档**: https://your-username.github.io/WasmSentinel/api/

## 🔧 自定义配置

### 自定义域名
如果您有自定义域名，可以：

1. 在 `demo-website/` 目录下创建 `CNAME` 文件：
```bash
echo "your-domain.com" > demo-website/CNAME
```

2. 在域名服务商处配置 DNS：
```
Type: CNAME
Name: www (或其他子域名)
Value: your-username.github.io
```

### 添加 Google Analytics
在 `demo-website/index.html` 的 `<head>` 部分添加：

```html
<!-- Google Analytics -->
<script async src="https://www.googletagmanager.com/gtag/js?id=GA_TRACKING_ID"></script>
<script>
  window.dataLayer = window.dataLayer || [];
  function gtag(){dataLayer.push(arguments);}
  gtag('js', new Date());
  gtag('config', 'GA_TRACKING_ID');
</script>
```

### 添加更多页面
在 `demo-website/` 目录下创建新的 HTML 文件，它们将自动部署到相应路径。

## 📊 监控和维护

### 查看部署状态
1. 进入 GitHub 仓库的 "Actions" 标签页
2. 查看 "Deploy Demo Website to GitHub Pages" 工作流
3. 点击具体的运行记录查看详细日志

### 部署失败排查
常见问题及解决方案：

1. **权限不足**
   - 检查 Actions 权限设置
   - 确保启用了 Pages 功能

2. **构建失败**
   - 查看 Actions 日志中的错误信息
   - 检查文件路径是否正确

3. **页面无法访问**
   - 等待 5-10 分钟让 DNS 生效
   - 检查 Pages 设置中的源配置

### 更新演示内容
只需修改 `demo-website/` 目录下的文件，推送到 GitHub 即可自动更新演示网站。

## 🎯 最佳实践

### SEO 优化
- ✅ 已包含 sitemap.xml
- ✅ 已设置适当的 meta 标签
- ✅ 使用语义化 HTML 结构
- ✅ 响应式设计支持移动设备

### 性能优化
- ✅ 启用 Gzip 压缩
- ✅ 静态资源缓存
- ✅ 图片优化
- ✅ 最小化 CSS/JS

### 安全考虑
- ✅ HTTPS 自动启用
- ✅ 安全的内容类型头
- ✅ 防止点击劫持
- ✅ CSP 内容安全策略

## 📚 相关文档

- [GitHub Pages 官方文档](https://docs.github.com/en/pages)
- [GitHub Actions 文档](https://docs.github.com/en/actions)
- [演示指南](./DEMO.md)
- [项目文档](./README.md)

---

**部署成功后，别忘了更新 README.md 中的演示链接！** 🎉
