# -*- coding: UTF-8 -*-
import hashlib
import os
import sys
from datetime import datetime, timedelta, timezone
from distutils.util import strtobool
from pathlib import Path
import json
import time

from dotenv import find_dotenv, load_dotenv
from sanic import Sanic
from sanic.response import Request, html, json, redirect, text
from sanic_ext import Extend, render
from sanic_session import InMemorySessionInterface, Session

from aes_model import AEScryptor
from verification_model import verification

app = Sanic('MyApp')
# 修改静态文件配置，添加缓存控制
app.static(
    '/static', 
    './templates/static', 
    name='get_static',
    # 添加缓存控制
    strict_slashes=True
)
session = Session(app, interface=InMemorySessionInterface())
# 加载env配置环境变量
load_dotenv(find_dotenv(str(Path.cwd().joinpath('.env'))))
app.config['HOST'] = os.getenv('HOST')
app.config['PORT'] = os.getenv('PORT')
app.config['DEBUG'] = os.getenv('DEBUG')
app.config['AUTO_RELOAD'] = os.getenv('AUTO_RELOAD')
# CORS跨域资源共享
app.config['CORS_ORIGINS'] = '*'
Extend(app)
# 初始化验证模型类
verify = verification()


# 创建请求中间件
@app.middleware('request')
async def get_request_middleware(request):
    # 添加请求时间戳，用于调试
    request.ctx.start_time = time.time()
    
    # 截取到login请求进行是否开启网络验证判断,如果关闭则直接通过.
    if request.path.split('/')[1] == 'login':
        if not strtobool(os.getenv('NETWORK_AUTH')):
            return json({'code': 10000, 'msg': '未开启网络验证直接通过验证', 'expireDate': '2099-12-31 23:59:59'})
    # 截取到admin分类请求的路径进行权限认证
    if len(request.path.split('/')) >= 3:  # 修复索引错误
        if request.path.split('/')[1] == 'admin' and request.path.split('/')[2] != 'login':
            if not strtobool(os.getenv('DEBUG')):  # 如果DEBUG模式等于True直接跳过登录验证
                if not request.ctx.session.get('admin_login_status'):
                    return redirect('/admin/login')


# 添加响应中间件处理CORS和缓存控制
@app.middleware('response')
async def add_security_headers(request, response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
    
    # 对静态文件和其他响应分别处理缓存控制
    if request.path.startswith('/static/'):
        # 静态文件：可以适当缓存，但添加版本控制
        response.headers['Cache-Control'] = 'public, max-age=3600'  # 1小时缓存
    else:
        # 动态内容：完全禁用缓存
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        response.headers['X-Accel-Expires'] = '0'  # 针对Nginx
    
    # 添加调试信息
    if hasattr(request.ctx, 'start_time'):
        processing_time = time.time() - request.ctx.start_time
        response.headers['X-Processing-Time'] = str(processing_time)


# 异常处理
@app.exception(Exception)
async def handle_exception(request, exception):
    # 处理JSON解析错误等
    if isinstance(exception, json.JSONDecodeError):
        return json({'code': 400, 'msg': '无效的JSON数据'})
    return json({'code': 500, 'msg': '服务器内部错误'})


# http://127.0.0.1:8081
@app.get('/')
async def index(request: Request):
    return html('作者：@jiayouzl，魔改：@Tarktip</br>服务器时间：' + verify.get_server_time())


@app.post('/reg')
async def reg(request: Request):
    parametes = request.json
    machineCode = parametes['machineCode']
    if len(machineCode) > 32:
        return json({'code': 10012, 'msg': '非法的机器码长度'})
    # 取现行时间(2022-09-10 12:48:08)
    expire_date_time = datetime.now(timezone(timedelta(hours=8))).strftime('%Y-%m-%d %H:%M:%S')
    if strtobool(os.getenv('IS_TRIAL')):
        # 增加*分钟
        expire_date_time = (datetime.now(timezone(timedelta(hours=8))) + timedelta(minutes=int(os.getenv('TRIAL_TIME')))).strftime('%Y-%m-%d %H:%M:%S')
    # 获取可选的应用分类和备注字段，默认为空字符串
    app_category = parametes.get('app_category', '')
    remark = parametes.get('remark', '')
    result = verify.reg(machineCode, str(expire_date_time), app_category, remark)
    return json(result)


@app.post('/login')
async def login(request: Request):
    parametes = request.json
    # Api接口签名认证
    key = 'rrm652gz4atq7jqc'
    timestamp = request.headers.get('timestamp')
    sign = request.headers.get('sign')
    if not timestamp or not sign:
        return json({'code': 10013, 'msg': '非法的签名'})
    _sign_str = parametes['machineCode'] + timestamp + key
    _sign = hashlib.md5(_sign_str.encode(encoding='utf-8')).hexdigest()
    if sign != _sign:
        return json({'code': 10014, 'msg': '非法的签名'})
    
    # 获取用户选择的加密方式
    user_aes_config = verify.get_user_aes_config(parametes['machineCode'])
    if user_aes_config:
        key = user_aes_config['key']
        iv = user_aes_config['iv']
    else:
        # 使用默认加密
        key = 'vqwn3p22uics8xv8'  # 16位
        iv = 's0Q~ioZ(AYJxyvLQ'  # 16位
    
    result = verify.login(parametes['machineCode'])
    
    #aes加密返回数据
    aes = AEScryptor(key=key, iv=iv, paddingMode='ZeroPadding', characterSet='utf-8')
    rData = aes.encryptFromString(str(result))
    return text(rData.toBase64())


@app.post('/recharge')
async def recharge(request: Request):
    parametes = request.json
    result = verify.recharge(parametes['machineCode'], parametes['card_number'], parametes['card_password'])
    return json(result)


# 登录页面 - 支持GET和POST
@app.route('/admin/login', methods=['GET', 'POST'])
async def admin_login(request: Request):
    if request.method == 'GET':
        # 添加时间戳防止缓存
        timestamp = int(time.time())
        return await render('login.html', status=200, context={'timestamp': timestamp})
    else:
        # POST请求处理
        user = request.form.get('user')
        password = request.form.get('pass')
        if user == os.getenv('ADMIN_USER') and password == os.getenv('ADMIN_PASS'):
            # 写入session
            request.ctx.session['admin_login_status'] = True
            # 添加延迟以确保session保存
            await asyncio.sleep(0.1)
            # 使用303 See Other确保重定向正确
            return redirect('/admin/user_info', status=303)
        else:
            return html('管理员账号或密码错误</br><a href=# onclick="javascript:history.back(-1);">返回上一页</a>')


@app.get('/admin/logout')
async def admin_logout(request: Request):
    # 清除session
    request.ctx.session.clear()
    return redirect('/admin/login', status=303)


# 充值卡管理
# http://127.0.0.1:8081/admin/card_info?page=1
@app.get('/admin/card_info/')
@app.ext.template('card_info.html')
async def card_info(request: Request):
    try:
        page = 1
        if request.args.get('page'):
            try:
                page = int(request.args.get('page'))
            except ValueError:
                page = 1
        
        card_info = verify.get_card(page, 20)
        
        # 确保有 all_page 键
        all_page = card_info.get('all_page', 1)
        
        home_page = 1
        previous_page = max(1, page - 1)
        next_page = min(all_page, page + 1) if all_page > 0 else 1
        end_page = max(1, all_page)
        
        # 添加时间戳防止缓存
        timestamp = int(time.time())
        
        return {
            'title': '充值卡管理', 
            'card_data': card_info.get('data', []), 
            'page': [home_page, previous_page, next_page, end_page],
            'timestamp': timestamp
        }
    except Exception as e:
        print(f"card_info route error: {e}")
        # 返回默认的空数据
        return {
            'title': '充值卡管理', 
            'card_data': [], 
            'page': [1, 1, 1, 1],
            'timestamp': int(time.time())
        }

# http://127.0.0.1:8081/admin/card_info/delete?key=20220902DHOPD
@app.get('/admin/card_info/delete')
async def card_info_delete(request: Request):
    key = request.args.get('key')
    result = verify.delete_card(key)
    return json(result)


# http://127.0.0.1:8081/admin/card_info/search?key=20220902DHOPD
@app.get('/admin/card_info/search')
async def card_info_search(request: Request):
    key = request.args.get('key')
    result = verify.search_card(key)
    return json(result)


@app.post('/admin/card_info/make')
async def make_card(request: Request):
    parametes = request.json
    result = verify.make_new_card(int(parametes['number']), int(parametes['days']))
    return json(result)


# 用户管理
@app.get('/admin/user_info')
@app.ext.template('user_info.html')
async def user_info(request: Request):
    try:
        page = 1 if (request.args.get('page') is None) else int(request.args.get('page'))
    except:
        page = 1
    user_info = verify.get_user(page, 20)
    # 获取所有应用分类
    app_categories = verify.get_app_categories()
    # 获取所有AES密钥配置
    aes_configs = verify.get_aes_configs()
    home_page = 1
    previous_page = 1 if (page - 1 == 0) else page - 1
    next_page = user_info['all_page'] if (page + 1 > user_info['all_page']) else page + 1
    end_page = user_info['all_page']
    
    # 添加时间戳防止缓存
    timestamp = int(time.time())
    
    return {
        'title': '用户管理', 
        'user_data': user_info['data'], 
        'page': [home_page, previous_page, next_page, end_page], 
        'app_categories': app_categories,
        'aes_configs': aes_configs,
        'timestamp': timestamp
    }


# 修改用户过期时间
@app.post('/admin/user_info/update')
async def user_update(request: Request):
    parametes = request.json
    result = verify.update_user(parametes['machine_code'], parametes['expire_date'])
    return json(result)


# 删除用户
@app.get('/admin/user_info/delete')
async def user_info_delete(request: Request):
    key = request.args.get('key')
    result = verify.delete_user(key)
    return json(result)


# 查询用户
@app.get('/admin/user_info/search')
async def user_info_search(request: Request):
    key = request.args.get('key')
    result = verify.search_user(key)
    return json(result)


# 添加应用分类
@app.post('/admin/app_category/add')
async def add_app_category(request: Request):
    parametes = request.json
    result = verify.add_app_category(parametes['name'])
    return json(result)


# 删除应用分类
@app.post('/admin/app_category/delete')
async def delete_app_category(request: Request):
    parametes = request.json
    result = verify.delete_app_category(parametes['name'])
    return json(result)


# 更新用户的应用分类
@app.post('/admin/user_info/update_app')
async def update_user_app(request: Request):
    parametes = request.json
    result = verify.update_user_app(parametes['machine_code'], parametes['app_name'])
    return json(result)


# 更新用户备注
@app.post('/admin/user_info/update_remark')
async def update_user_remark(request: Request):
    parametes = request.json
    result = verify.update_user_remark(parametes['machine_code'], parametes['remark'])
    return json(result)


# 获取AES配置列表
@app.get('/admin/aes_configs')
async def get_aes_configs(request: Request):
    result = verify.get_aes_configs()
    return json(result)


# 生成新的AES配置
@app.post('/admin/aes_configs/generate')
async def generate_aes_config(request: Request):
    result = verify.generate_aes_config()
    return json(result)


# 删除AES配置
@app.post('/admin/aes_configs/delete')
async def delete_aes_config(request: Request):
    parametes = request.json
    result = verify.delete_aes_config(parametes['config_id'])
    return json(result)


# 更新用户的AES配置
@app.post('/admin/user_info/update_aes')
async def update_user_aes(request: Request):
    parametes = request.json
    result = verify.update_user_aes(parametes['machine_code'], parametes['aes_config_id'])
    return json(result)


if __name__ == '__main__':
    import asyncio
    app.run(host=app.config['HOST'], port=int(app.config['PORT']), debug=strtobool(app.config['DEBUG']), auto_reload=strtobool(app.config['AUTO_RELOAD']), access_log=True, workers=1)
