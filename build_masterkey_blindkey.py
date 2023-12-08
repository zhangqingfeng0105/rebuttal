# -*- coding: utf-8 -*-

import datetime
import struct
import base64
from blind_key_algorithm import *


def build_onion_address(pubkey_string):
    '''
    :param pubkey_string:  
    :return:
    '''

    # Checksum is built like so:
    #   CHECKSUM = SHA3(".onion checksum" || PUBKEY || VERSION)
    PREFIX = ".onion checksum".encode()
    PUBKEY = bytearray.fromhex(pubkey_string)
    VERSION = 3

    #15s32s1b
    data = struct.pack('15s32s1b', PREFIX, PUBKEY, VERSION)
    checksum = hashlib.sha3_256(data).digest()

    # Onion address is built like so:
    #   onion_address = base32(PUBKEY || CHECKSUM || VERSION) + ".onion"

    address = struct.pack('!32s2sb', PUBKEY, checksum, VERSION)
    onion_addr = base64.b32encode(address).decode().lower()
    return onion_addr

def extract_master_pubkey(onion_addresss):
    '''
    :param onion_addresss:
    :return:
    '''
    onion_b32decode = base64.b32decode(onion_addresss.upper().encode())
    master_key = struct.unpack('!32s2sb',onion_b32decode)[0]
    return master_key

def calculate_period(end_time=None):
    '''
    :param end_time:  2023-06-07
    :return:
    '''
    if not end_time:
        time_diff = (datetime.datetime.utcnow() - datetime.datetime.strptime("1970-01-01 12:00:00", "%Y-%m-%d %H:%M:%S")).total_seconds()
    else:
        end_time = end_time + " 12:00:00"
        time_diff = (datetime.datetime.strptime(end_time, "%Y-%m-%d %H:%M:%S")- datetime.datetime.strptime("1970-01-01 12:00:00", "%Y-%m-%d %H:%M:%S")).total_seconds()
    return int(time_diff/86400)

def build_blind_key(master_pubkey,time_control=None,is_previous_blindkey=False):
    '''
    :param master_pubkey:
    :return:
    '''
    str_ed25519_basepoint = "(15112221349535400772501151409588531511454012693041857206046113283949847762202, 46316835694926478169428394003475163141307993866256225615783033603165251855960)"

    nonce_prefix = "key-blind".encode()
    period_num = calculate_period(time_control)
    if is_previous_blindkey:
        period_num -= 1
    period_length = 1440
    nonce = struct.pack('!9sQQ', nonce_prefix, period_num, period_length)

    blind_str = "Derive temporary signing key".encode()
    # PUBKEY = bytearray.fromhex(master_pubkey)
    PUBKEY = master_pubkey
    str_ed25519_basepoint_byte = str_ed25519_basepoint.encode()

    data = struct.pack('29s32s158s25s', blind_str, PUBKEY, str_ed25519_basepoint_byte, nonce)
    blind_key = hashlib.sha3_256(data).digest()
    return blind_key


def blindPK(pk, param):
    '''
    :param pk:
    :param param:
    :return:
    '''
    mult = 2**(b-2) + sum(2**i * bit(param,i) for i in range(3,b-2))
    P = decodepoint(pk)
    return encodepoint(scalarmult(P, mult))

def main_helper():
    '''
    :return:
    '''
    pubkey_string = "5492FEFE4C5F5B2ED70BBB6B00A3E8551DE1B5EE06F6791346CE98AB0C891704"
    onion_address = build_onion_address(pubkey_string)
    master_pubkey_byte = extract_master_pubkey(onion_address)
    blind_key_param_byte = build_blind_key(master_pubkey_byte)
    blinke_pubkey_byte = blindPK(master_pubkey_byte,blind_key_param_byte)
    print(blinke_pubkey_byte.hex().upper())




