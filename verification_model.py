# -*- coding: UTF-8 -*-

import math
import time
import random
import string
from datetime import datetime, timedelta, timezone
from pathlib import Path
from random import Random

from dotenv import find_dotenv, load_dotenv
from tinydb import Query, TinyDB


class verification(object):

    def __init__(self) -> None:
        # 确保数据库目录存在
        Path('./database').mkdir(exist_ok=True)
        Path('./log').mkdir(exist_ok=True)
        
        # 设置数据库文件
        self.db_user = TinyDB('./database/db.json', indent=4)
        self.db_user.default_table_name = 'user'
        self.db_card = TinyDB('./database/db.json', indent=4)
        self.db_card.default_table_name = 'card'
        
        # 设置时区
        self.tz = timezone(timedelta(hours=8))
        # 加载env配置环境变量
        load_dotenv(find_dotenv(str(Path.cwd().joinpath('.env'))))
        # 初始化默认AES配置
        self._init_default_aes_config()

    def _init_default_aes_config(self):
        """初始化默认AES配置"""
        aes_configs = self.db_user.table('aes_configs')
        if not aes_configs.contains(Query().config_id == 'default'):
            aes_configs.insert({
                'config_id': 'default',
                'name': '默认加密',
                'key': '更改一下自己用的，或参考源代码',
                'iv': '更改一下自己用的，或参考源代码',
                'created_time': datetime.now(self.tz).strftime('%Y-%m-%d %H:%M:%S'),
                'is_default': True
            })

    # 机器码注册
    def reg(self, machine_code: str, expire_date: str, app_category='', remark=''):
        result_search = self.db_user.get(Query().machine_code == machine_code)
        if result_search in [None, []]:
            result_insert = self.db_user.insert({
                'machine_code': machine_code, 
                'expire_date': expire_date, 
                'reg_date': datetime.now(self.tz).strftime('%Y-%m-%d %H:%M:%S'),
                'app_category': app_category,
                'remark': remark,
                'aes_config_id': 'default'  # 默认使用默认加密
            })
            if result_insert > 0:
                return {'code': 10000, 'msg': '机器码注册成功', 'expireDate': expire_date}
            else:
                return {'code': 10011, 'msg': '机器码注册失败'}
        else:
            return {'code': 10010, 'msg': '机器码已存在'}
        
    # 机器码登录验证
    def login(self, machine_code: str):
        result = self.db_user.search(Query().machine_code == machine_code)
        # 判断机器码是否存在数据库中
        if result not in [None, []]:
            # 判断该机器码是否过期
            if result[0]['expire_date'] > datetime.now(self.tz).strftime('%Y-%m-%d %H:%M:%S'):
                return {'code': 10000, 'msg': '机器码未过期', 'expireDate': result[0]['expire_date'], 'nowtime': int(time.time())}
            else:
                return {'code': 10011, 'msg': '机器码已过期', 'expireDate': result[0]['expire_date'], 'nowtime': int(time.time())}
        else:
            return {'code': 10010, 'msg': '机器码不存在', 'nowtime': int(time.time())}

    # 获取用户的AES配置
    def get_user_aes_config(self, machine_code: str):
        user = self.db_user.get(Query().machine_code == machine_code)
        if user and 'aes_config_id' in user:
            aes_configs = self.db_user.table('aes_configs')
            config = aes_configs.get(Query().config_id == user['aes_config_id'])
            if config:
                return {'key': config['key'], 'iv': config['iv']}
        # 返回默认配置
        aes_configs = self.db_user.table('aes_configs')
        default_config = aes_configs.get(Query().config_id == 'default')
        if default_config:
            return {'key': default_config['key'], 'iv': default_config['iv']}
        return None

    # 机器码充值
    def recharge(self, machine_code: str, card_number: str, card_pass: str):
        # 查询机器码是否存在
        result_user = self.db_user.get(Query().machine_code == machine_code)
        if result_user in [None, []]:
            return {'code': 10030, 'msg': '机器码不存在'}
        # 查询充值卡信息
        result_card = self.db_card.get(Query().card_number == card_number and Query().card_pass == card_pass)
        if result_card not in [None, []]:
            if not result_card.get('used'):
                user_expire_date = result_user.get('expire_date')
                card_days = result_card.get('days')
                # 判断机器码授权日期是否过期
                if user_expire_date >= datetime.now(self.tz).strftime('%Y-%m-%d %H:%M:%S'):
                    new_date_time = datetime.strptime(user_expire_date, '%Y-%m-%d %H:%M:%S') + timedelta(days=card_days)
                    new_date_time = new_date_time.strftime('%Y-%m-%d %H:%M:%S')
                else:
                    new_date_time = datetime.now(self.tz) + timedelta(days=card_days)
                    new_date_time = new_date_time.strftime('%Y-%m-%d %H:%M:%S')
                # 修改机器码授权日期
                result_user_update = self.db_user.update({'expire_date': new_date_time}, Query().machine_code == machine_code)
                if len(result_user_update) == 1:
                    # 修改充值卡使用状态
                    result_card_update = self.db_card.update({
                            'used': True,
                            'used_machine_code': result_user.get('machine_code'),
                            'used_time': datetime.now(self.tz).strftime('%Y-%m-%d %H:%M:%S')
                        }, Query().card_number == card_number and Query().card_pass == card_pass)
                    if len(result_card_update) != 1:
                        # 追加写入日志文件
                        with open('./log/error.log', 'a') as f:
                            f.write(self.get_server_time() + '\t充值卡使用状态修改失败\t' + machine_code + '\t' + card_number + '\t' + card_pass + '\r\n')
                    return {'code': 10000, 'msg': '充值成功', 'expireDate': new_date_time}
                else:
                    return {'code': 10033, 'msg': '充值失败，请于管理员联系。'}
            else:
                return {'code': 10032, 'msg': '充值卡已使用'}
        else:
            return {'code': 10031, 'msg': '充值卡不存在'}

    # 充值卡生成
    def make_new_card(self, number: int, days: int):
        # 批量生成充值卡
        insert_result = self.db_card.insert_multiple({'card_number': self.new_card_number(), 'card_pass': self.random_str(8), 'days': days, 'used': False, 'used_machine_code': '', 'used_time': ''} for i in range(number))
        if insert_result not in [None, []]:
            print_result = []
            for i in insert_result:
                get_data = self.db_card.get(doc_id=i)
                print_result.append([get_data["card_number"], get_data["card_pass"], get_data["days"]])
            return {'code': 10000, 'msg': '充值卡生成成功', 'data': print_result}
        else:
            return {'code': 10020, 'msg': '充值卡生成失败'}

    # 获取充值卡列表(分页)
    def get_card(self, page: int, limit: int):
        try:
            # 查询充值卡列表
            result_card = self.db_card.all()
            # 逆序排列
            result_card.reverse()
            # 总条数
            count_data = len(result_card)
            # 向上取整得到总页数
            all_page = math.ceil(len(result_card) / limit) if result_card else 1
            
            if result_card:  # 简化判断条件
                result_card = result_card[(page - 1) * limit:page * limit]
                result_card_list = []
                for i in result_card:
                    result_card_list.append([
                        i.get("card_number", ""), 
                        i.get("card_pass", ""), 
                        i.get("days", 0), 
                        str(i.get("used", False)), 
                        i.get("used_machine_code", ""), 
                        i.get("used_time", "")
                    ])
                return {
                    'code': 10000, 
                    'msg': '查询成功', 
                    'count_data': count_data, 
                    'page': page, 
                    'all_page': all_page, 
                    'data': result_card_list
                }
            else:
                # 即使没有数据也要返回完整结构
                return {
                    'code': 10021, 
                    'msg': '查询失败或无数据', 
                    'count_data': 0, 
                    'page': page, 
                    'all_page': 1, 
                    'data': []
                }
        except Exception as e:
            print(f"get_card error: {e}")
            # 确保返回完整结构
            return {
                'code': 10021, 
                'msg': f'查询失败: {str(e)}', 
                'count_data': 0, 
                'page': page, 
                'all_page': 1, 
                'data': []
            }

    # 删除充值卡
    def delete_card(self, card_number: str):
        result_card = self.db_card.remove(Query().card_number == card_number)
        if len(result_card) == 1:
            return {'code': 10000, 'msg': '充值卡删除成功'}
        else:
            return {'code': 10022, 'msg': '充值卡删除失败'}

    # 充值卡查询
    def search_card(self, card_number: str):
        result_card = self.db_card.get(Query().card_number == card_number)
        if result_card not in [None, []]:
            return {'code': 10000, 'msg': '查询成功', 'data': [result_card["card_number"], result_card["card_pass"], result_card["days"], str(result_card["used"]), result_card["used_machine_code"], result_card["used_time"]]}
        else:
            return {'code': 10023, 'msg': '该充值卡不存在'}

    # 获取用户(机器码)列表(分页)
    def get_user(self, page: int, limit: int):
        try:
            # 查询用户列表
            result_user = self.db_user.all()
            # 逆序排列
            result_user.reverse()
            # 总条数
            count_data = len(result_user)
            # 向上取整得到总页数
            all_page = math.ceil(len(result_user) / limit) if result_user else 1
            
            if result_user:
                result_user = result_user[(page - 1) * limit:page * limit]
                result_user_list = []
                for i in result_user:
                    result_user_list.append([
                        i.get("machine_code", ""), 
                        i.get("expire_date", ""), 
                        i.get("reg_date", ""),
                        i.get("app_category", ""),
                        i.get("remark", ""),
                        i.get("aes_config_id", "default")
                    ])
                return {
                    'code': 10000, 
                    'msg': '查询成功', 
                    'count_data': count_data, 
                    'page': page, 
                    'all_page': all_page, 
                    'data': result_user_list
                }
            else:
                return {
                    'code': 10022, 
                    'msg': '查询失败或无数据', 
                    'count_data': 0, 
                    'page': page, 
                    'all_page': 1, 
                    'data': []
                }
        except Exception as e:
            print(f"get_user error: {e}")
            return {
                'code': 10022, 
                'msg': f'查询失败: {str(e)}', 
                'count_data': 0, 
                'page': page, 
                'all_page': 1, 
                'data': []
            }

    # 修改用户(机器码)过期时间
    def update_user(self, machine_code: str, expire_date: str):
        result_user = self.db_user.update({'expire_date': expire_date}, Query().machine_code == machine_code)
        if len(result_user) == 1:
            return {'code': 10000, 'msg': '修改成功'}
        else:
            return {'code': 10024, 'msg': '机器码过期时间修改失败'}

    # 删除用户(机器码)
    def delete_user(self, machine_code: str):
        result_user = self.db_user.remove(Query().machine_code == machine_code)
        if len(result_user) == 1:
            return {'code': 10000, 'msg': '用户删除成功'}
        else:
            return {'code': 10025, 'msg': '用户删除失败'}

    # 用户(机器码)查询
    def search_user(self, machine_code: str):
        result_user = self.db_user.get(Query().machine_code == machine_code)
        if result_user not in [None, []]:
            return {'code': 10000, 'msg': '查询成功', 'data': [
                result_user["machine_code"], 
                result_user["expire_date"], 
                result_user["reg_date"],
                result_user.get("app_category", ""),
                result_user.get("remark", ""),
                result_user.get("aes_config_id", "default")
            ]}
        else:
            return {'code': 10026, 'msg': '该用户不存在'}

    # 获取所有应用分类
    def get_app_categories(self):
        app_categories = self.db_user.table('app_categories')
        return [item['name'] for item in app_categories.all()]

    def add_app_category(self, category_name):
        app_categories = self.db_user.table('app_categories')
        # 检查是否已存在
        if not app_categories.contains(Query().name == category_name):
            app_categories.insert({'name': category_name})
            return {'code': 10000, 'msg': '应用分类添加成功'}
        return {'code': 10040, 'msg': '应用分类已存在'}

    def delete_app_category(self, category_name):
        app_categories = self.db_user.table('app_categories')
        # 先检查应用分类是否存在
        if not app_categories.contains(Query().name == category_name):
            return {'code': 10041, 'msg': '应用分类不存在'}
        
        # 删除应用分类前，先将使用该分类的用户的应用分类清空
        self.db_user.update({'app_category': ''}, Query().app_category == category_name)
        
        # 然后删除应用分类
        result = app_categories.remove(Query().name == category_name)
        if len(result) > 0:
            return {'code': 10000, 'msg': '应用分类删除成功'}
        return {'code': 10041, 'msg': '应用分类删除失败'}

    def update_user_app(self, machine_code, app_name):
        result = self.db_user.update({'app_category': app_name}, Query().machine_code == machine_code)
        if len(result) == 1:
            return {'code': 10000, 'msg': '应用分类更新成功'}
        return {'code': 10042, 'msg': '应用分类更新失败'}

    def update_user_remark(self, machine_code, remark):
        result = self.db_user.update({'remark': remark}, Query().machine_code == machine_code)
        if len(result) == 1:
            return {'code': 10000, 'msg': '备注更新成功'}
        return {'code': 10043, 'msg': '备注更新失败'}

    # AES配置管理
    def get_aes_configs(self):
        aes_configs = self.db_user.table('aes_configs')
        configs = []
        for config in aes_configs.all():
            configs.append({
                'config_id': config['config_id'],
                'name': config['name'],
                'created_time': config['created_time'],
                'is_default': config.get('is_default', False)
            })
        return configs

    def generate_aes_config(self):
        # 生成16位随机key和iv
        key = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
        iv = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
        
        config_id = str(int(time.time()))
        name = f"加密配置_{datetime.now(self.tz).strftime('%Y%m%d%H%M%S')}"
        
        aes_configs = self.db_user.table('aes_configs')
        result = aes_configs.insert({
            'config_id': config_id,
            'name': name,
            'key': key,
            'iv': iv,
            'created_time': datetime.now(self.tz).strftime('%Y-%m-%d %H:%M:%S'),
            'is_default': False
        })
        
        if result:
            return {'code': 10000, 'msg': 'AES配置生成成功', 'config_id': config_id, 'name': name}
        else:
            return {'code': 10050, 'msg': 'AES配置生成失败'}

    def delete_aes_config(self, config_id):
        if config_id == 'default':
            return {'code': 10051, 'msg': '默认加密配置不可删除'}
        
        aes_configs = self.db_user.table('aes_configs')
        # 检查是否有用户使用此配置
        users_with_config = self.db_user.search(Query().aes_config_id == config_id)
        if users_with_config:
            # 将这些用户的配置重置为默认
            for user in users_with_config:
                self.db_user.update({'aes_config_id': 'default'}, Query().machine_code == user['machine_code'])
        
        result = aes_configs.remove(Query().config_id == config_id)
        if len(result) > 0:
            return {'code': 10000, 'msg': 'AES配置删除成功'}
        return {'code': 10052, 'msg': 'AES配置删除失败'}

    def update_user_aes(self, machine_code, aes_config_id):
        result = self.db_user.update({'aes_config_id': aes_config_id}, Query().machine_code == machine_code)
        if len(result) == 1:
            return {'code': 10000, 'msg': 'AES配置更新成功'}
        return {'code': 10053, 'msg': 'AES配置更新失败'}

    # 工具函数集
    def new_card_number(self):
        local_time = time.strftime('%Y%m%d', time.localtime(time.time()))
        card_number = local_time + self.random_str(5)
        return card_number

    def random_str(self, randomlength=8):
        result_str = ''
        chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        length = len(chars) - 1
        random = Random()
        for i in range(randomlength):
            result_str += chars[random.randint(0, length)]
        return result_str

    def get_server_time(self):
        return datetime.now(self.tz).strftime('%Y-%m-%d %H:%M:%S')


if __name__ == '__main__':
    v = verification()
    # print(v.reg('123456789111111', '2021-12-31 13:29:59'))
    # for i in range(20):
    #     print(v.reg(v.random_str(16), '2021-12-31 13:29:59'))
    # print(v.login('123456789111111'))
    # print(v.make_new_card(100, 90))
    # print(v.recharge('223456789111111', '20220901BRDID', 'HGVSPQGE'))
    # print(v.get_card(1, 5))  # (1, 5)=[0, 5],(2, 5)=[5, 10]
    # print(v.delete_card('20220905ZQUCY'))
    # print(v.search_card('20220905NLHYL'))

    # print(v.get_user(1, 5))  # (1, 5)=[0, 5],(2, 5)=[5, 10]
    # print(v.update_user('123456789111111', '2021-12-31 13:29:59'))
    # print(v.delete_user('123456789111111'))
    # print(v.search_user('123456789111111'))
