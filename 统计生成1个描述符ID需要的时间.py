# -*- coding: utf-8 -*-
# @Time: 2023/12/5 18:51
# @Auth: ZhangQingFeng
# @File: 统计生成1个描述符ID需要的时间.py
# @IDE: PyCharm
# @Email: zhangqingfeng0105@163.com
import datetime
import struct
import base64
from blind_key_algorithm import *
import build_masterkey_blindkey as bmb


def build_descriptor_id(blind_pub_key, replica, period_num):
    '''
    构建描述符ID
    descriptor-id = SHA3("store-at-idx" |blinded_public_key |INT_8(replica) | INT_8(period_length)|INT_8(period_num)
    :param blind_pub_key:
    :param replica:
    :param period_num:
    :return:
    '''
    prefix = 'store-at-idx'.encode()
    # blind_pub_key_encode = blind_pub_key.encode()
    blind_pub_key_encode = blind_pub_key
    period_length = 1440
    data = struct.pack('!12s32sQQQ', prefix, blind_pub_key_encode, replica, period_length, period_num)
    hs_index = hashlib.sha3_256(data).hexdigest()
    return hs_index.upper()

def calculate_create_desc_time():
    '''
    测试生成描述符ID所需要的时间
    :return:
    '''


    master_pubkey_byte = "5492FEFE4C5F5B2ED70BBB6B00A3E8551DE1B5EE06F6791346CE98AB0C891704".encode()
    end_time = '2023-07-21'

    now = datetime.datetime.now()

    # 根据主身份公钥生成盲化公钥的param部分
    blind_key_param_byte_current = bmb.build_blind_key(master_pubkey_byte, end_time)
    # 根据主身份公钥和param生成盲化公钥
    blind_pubkey_byte_current = bmb.blindPK(master_pubkey_byte, blind_key_param_byte_current)

    old_now = datetime.datetime.now()
    old_diff_time = ((old_now - now).microseconds)//1000

    replica = 1
    period_num = bmb.calculate_period(end_time)
    desc_id = build_descriptor_id(blind_pubkey_byte_current, replica, period_num)
    # print(desc_id)
    new_now = datetime.datetime.now()
    diff_time = ((new_now - now).microseconds)//1000
    # print("计算1个描述符ID需要花费：{}毫秒".format(diff_time)
    return diff_time, old_diff_time

def main_helper():
    '''
    主程序入口
    :return:
    '''
    experiment_times = 100
    res = []
    blindkey_timecost = []
    for i in range(experiment_times):
        new_diff_time, old_diff_time = calculate_create_desc_time()
        res.append(new_diff_time)
        blindkey_timecost.append(old_diff_time)
    print("平均值：{}毫秒".format(sum(res)/len(res)))
    print("blindkey_timecost平均值：{}毫秒".format(sum(blindkey_timecost)/len(blindkey_timecost)))

if __name__ == '__main__':
    main_helper()