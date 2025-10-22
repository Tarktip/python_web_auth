<h2 align="center">极简网络验证Python3版 魔改优化</h2>
<p>一款轻量级的网络验证服务端应用程序，基于JSON改造的数据库，免去部署MySQL等数据库的烦恼，实现快速部署上线生产的目的。</p>
<h4 align="center">后台管理界面预览</h4>
<p align="center">
<img src="https://myimages.25531.com/20220915/iShot_2022-09-15_13.22.42.png" width="50%" height="50%" alt="Empty interface" />
<img src="https://myimages.25531.com/20220915/iShot_2022-09-15_13.23.11.png" width="50%" height="50%" alt="Empty interface" />
</p>

## 简介
<a target="_blank" href="https://github.com/jiayouzl/python_web_auth">看原版链接</a>


## 更新记录
`2025-10-23`

1. 优化后台反馈，修改数据 登录 删除数据 新增数据 可以立刻反馈，无需等待。
2. 去除修改确定按钮，修改数据立刻生效。
3. 增加应用验证分类。
4. 增加备注。
5. 增加自选aes模块加密解析，生成后在服务器后端db.json获取key以及iv进行修改解析。
6. 增加机器码位数检索。

ps：记得修改app.py api接口签名认证key，以及aes_model.py中的混淆data，文件都是原版默认的，修改后再使用

