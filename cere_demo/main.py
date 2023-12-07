import logging
import re
import struct
import sys
from dataclasses import dataclass

import serial
from twisted.internet import defer, reactor, task
from twisted.internet.serialport import SerialPort
from twisted.protocols.basic import LineReceiver

from cere_demo.console import embed
from cere_demo.constant import ESCROW_STATUS_STACK_BILL, RESP_BILL_DISABLED, BILL_ADDR, CHANGER_ADDR, BILL_ST, \
    BILL_ROUTING, ST, ESCROW_STATUS_RETURN_BILL
from cere_demo.tools import log_result, pretty, binary2dict, run_in_thread
from cere_demo.tools import mdb232_logger as logger
from blinker import signal

auto_rx = signal("auto_rx")


class TimeoutException(Exception):
    pass

class MDB232(LineReceiver):
    """威佛mdb->rs232"""

    timeout = 0.3

    def __init__(self):
        self.req = None
        # self.setRawMode()
        self.setLineMode()
        self.lock = defer.DeferredLock()
        self.data = bytearray()
        self.rx_bean = None

    def connectionMade(self):
        logger.debug("Connected")

    def lineReceived(self, line):
        rx_bean = RxBean(line)
        if rx_bean.target:  # 纸币机和硬币器 主动上报的数据
            if rx_bean.need_output:
                # auto_rx.send(rx_bean.asc_data)
                logger.info(f"auto rx: {rx_bean.asc_data}")
        else:
            logger.info(f"rx: {rx_bean.asc_data}")
            self.data = line
            self.rx_bean = rx_bean

    @log_result
    def call(self, req):
        return self.lock.run(self._call, req)

    @defer.inlineCallbacks
    def _call(self, req):
        self.data = bytearray()
        self.rx_bean = None
        if self.req:
            raise ValueError(
                "call %s while %s request in progress" % (
                    pretty(req), pretty(self.req)))
        self.req = req
        try:
            logger.info(f"tx: {pretty(req)}")
            self.transport.write(req)
        except Exception as e:
            logger.exception("Error while write to transport")
            self.req = None
            raise e
        # 限定等待 self.data的最大时间

        yield task.deferLater(reactor, self.timeout, defer.passthru, None)
        self.req = None

        if self.rx_bean:
            defer.returnValue(self.rx_bean)
        else:
            raise TimeoutException("Timeout")

    @log_result
    def mdb_init(self):
        return self.call('\x02\x85\x0A')


@dataclass
class RxBean:
    raw_data: bytes  # b'01 00 86 00 0A 01 00 C8 00 0F FF 01 05 0A 14 FF 00 8B '

    def __post_init__(self):
        self.parse()

    def checksum(self):

        if len(self.hex_data) == 1 or self.hex_data.startswith(BILL_ADDR) or self.hex_data.startswith(
                CHANGER_ADDR):  # 单字节或者设备主动报告 不需要校验
            return
        assert (sum(self.hex_data[:-1]) & 0xff) == self.hex_data[-1], f'Wrong checksum, data:{self.hex_data},' \
                                                                      f' chk:{self.hex_data[-1]:x}'
        self.with_sum = True

    @property
    def need_output(self):
        return self.hex_data != RESP_BILL_DISABLED

    def parse(self):
        self.target = ""
        self.with_sum = False
        try:
            self.asc_data = self.raw_data.decode('utf8')  # '01 00 86 00 0A 01 00 C8 00 0F FF 01 05 0A 14 FF 00 8B '
        except Exception:
            logger.exception(f"parsing: {self.raw_data}")

        self.hex_data = bytes.fromhex(
            self.asc_data)  # b'\x01\x00\x86\x00\n\x01\x00\xc8\x00\x0f\xff\x01\x05\n\x14\xff\x00\x8b'
        self.checksum()

        if self.hex_data.startswith(BILL_ADDR):
            self.target = BILL_ADDR
            self.parse_bill_data(self.hex_data[1:])
        elif self.hex_data.startswith(CHANGER_ADDR):
            self.target = CHANGER_ADDR
            self.parse_changer_data()

    def parse_bill_data(self, data):
        msgs = []
        for byte in data:
            if byte & 0x80:
                bill_route = (byte & 0x70) >> 4
                bill_type = byte & 0xF
                bill_route_msg = BILL_ROUTING.get(bill_route, bill_route)
                if isinstance(bill_route_msg, ST):
                    bill_route_msg = f"{bill_route_msg.name}/{bill_route_msg.note}"
                value = BillValidator.support_bills.get(bill_type, -1)
                msg = f"纸币类型{bill_type}(面额{value}): {bill_route_msg} "
            else:
                msg = BILL_ST.get(byte, byte)
            if isinstance(msg, ST):
                msg = f"{msg.name}/{msg.note}"
            msgs.append(msg)
        if self.need_output:
            logger.info(f"bill msg: {msgs}")

    def parse_changer_data(self):
        pass

    def __str__(self):
        return f"{self.asc_data}"


class MDBDevice:
    commands = {}

    def __init__(self, proto):
        self.proto = proto
        self.timeout = 0
        self.try_count = 3
        self._online = False

    def _set_online(self, online):
        if online == self._online:
            return
        self._online = online

        if online:
            self.go_online()
        else:
            self.go_offline()

    def go_online(self):
        pass

    def go_offline(self):
        pass

    @defer.inlineCallbacks
    def call(self, request, try_count=-1):
        if try_count == -1:
            try_count = self.try_count

        for i in range(try_count):
            try:
                result = yield self.proto.call(request)
                self._set_online(True)
                defer.returnValue(result)
            except Exception as e:
                logger.debug(f"call exception. {i=}")
                if i == try_count - 1:
                    self._set_online(False)
                    raise e

    def reset(self):
        """一般不需要发，微佛上电后自动复位"""
        return self.call(self.commands.get("reset", ""))


class BillValidator(MDBDevice):
    commands = {
        "reset": b"\x30",  # 复位设备
        "config": b"\x31",  # 获取设置信息
        'poll': b'\x33',  # 轮询 (vmc no need do this, wafer will poll device automatically)
        'bill_type': b'\x34',  # 设置纸币类型
        'escrow': b'\x35',  # 暂存
        'stacker': b'\x36'  # 查询钱箱是否满，以及钱箱中纸币数量
    }
    support_bills = {}

    def __init__(self, proto, bills):
        """
        :param proto: 协议
        :param bills: 支持哪些面额
        """
        super(BillValidator, self).__init__(proto)

        self._bills = bills
        # self.support_bills = {}

        '''
        # 01 00 86 00 0A 01 00 C8 00 0F FF 01 05 0A 14 FF 00 8B
        纸币器级别 01
        货币代码 00 86
        纸币 比例银子 00 0a
        小数点位数  01
        钱箱容量  00 c8
        纸币安全类别 00 0f 
        暂存功能  ff
        纸币面额  01 05 0a 14 ff 00....
        
        '''

    @defer.inlineCallbacks
    def get_config(self):
        rx_bean = yield self.call(self.commands["config"])
        # logger.info(f"{rx_bean}")
        hex_data = rx_bean.hex_data
        res = binary2dict(">BhhBhhB", hex_data[:11],
                          ['bill_level', 'currency_code', 'factor', 'precision', 'capacity', 'safe_level', 'escrow'])
        res["escrow"] = bool(res["escrow"])
        res["bill_type"] = []
        BillValidator.support_bills = {}
        for i, v in enumerate(hex_data[11:-1]):
            if v not in (0xff, 0):
                BillValidator.support_bills[i] = v
        res["bill_type"] = BillValidator.support_bills
        logger.info(f"纸币机配置 {res}")

        return res

    def escrow(self, status=ESCROW_STATUS_STACK_BILL):
        """默认参数吞钞"""
        return self.call(self.commands["escrow"] + status)

    def stack_bill(self):
        """吞钞"""
        self.escrow(status=ESCROW_STATUS_STACK_BILL)

    def return_bill(self):
        """退钞"""
        self.escrow(status=ESCROW_STATUS_RETURN_BILL)

    def start_accept(self, bill_mask=None):
        if bill_mask is None:
            bill_mask = 0xffffffff
        return self.bill_type(bills=bill_mask)

    def stop_accept(self):
        return self.bill_type(bills=0)

    def bill_type(self, bills):
        return self.call(self.commands["bill_type"] + struct.pack(">I", bills))


class Changer(MDBDevice):
    """硬币机"""

    commands = {
        'reset': b'\x08',
        'config': b'\x09',
        'tube_status': b'\x0A',
        'poll': b'\x0B',
        'coin_type': b'\x0C',
        'dispense': b'\x0D',
        'extend_dispense': b'\x0f\x02'  # 只有level 3才支持
    }

    support_coins = {}

    factor = 5   # 默认比例因子
    precision = 1  # 默认小数点位数


    @defer.inlineCallbacks
    def get_config(self):
        # 03 11 56 05 01 00 03 01 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 76
        rx_bean = yield self.call(self.commands["config"])
        # logger.info(f"{rx_bean}")
        hex_data = rx_bean.hex_data
        res = binary2dict(">BhBBh", hex_data[:7],
                          ['level', 'currency_code', 'factor', 'precision', 'tube_route'])
        BillValidator.support_coins = {}
        BillValidator.factor = res["factor"]
        BillValidator.precision = res["precision"]
        for i, v in enumerate(hex_data[7:-1]):
            if v not in (0xff, 0) and (1 << i) & res["tube_route"]:  # 如果钱管支持该类型
                BillValidator.support_coins[i] = (v * res["factor"]) / (res["precision"] * 10)
        res["coin_type"] = BillValidator.support_coins
        logger.info(f"硬币器配置 {res}")

        return res

    @defer.inlineCallbacks
    def tube_status(self):
        """查询钱管填充情况"""
        rx_bean = yield self.call(self.commands["tube_status"])
        hex_data = rx_bean.hex_data
        res = binary2dict(">h", hex_data[:2], ['tube_full_status'])
        res["full_tubes"] = [i for i in range(16) if res["tube_full_status"] & (1 << i)]
        res["coin_count"] = {}
        res.pop("tube_full_status", None)
        for i, v in enumerate(hex_data[2:-1]):
            if i < 3: # 只查前3种类型。如果今后需要扩展 再改大
                res["coin_count"][i] = v
        logger.info(f"钱管状态 {res}")
        return res

    def start_accept(self, coin_mask=None):
        if coin_mask is None:
            coin_mask = 0xffffffff
        return self.coin_type(bills=coin_mask)

    def stop_accept(self):
        return self.coin_type(bills=0)

    def coin_type(self, bills):
        return self.call(self.commands["coin_type"] + struct.pack(">I", bills))

    def extend_dispense(self, amount):
        """例如amount 1.5元， 1.5/factor*precision*10 = 3"""







@run_in_thread
def async_reactor():
    SerialPort(
        proto, '/dev/ttyUSB0', reactor,
        baudrate='9600', parity=serial.PARITY_NONE,
        bytesize=serial.EIGHTBITS, stopbits=serial.STOPBITS_ONE)
    # reactor.callLater(1, bill.get_config)
    # reactor.callLater(1, bill.get_config)
    # reactor.callLater(1, changer.get_config)
    reactor.callLater(1, changer.tube_status)
    # reactor.callLater(2, bill.stop_accept)
    # reactor.run()
    reactor.run(installSignalHandlers=False)


@auto_rx.connect
def receiver(msg):
    logger.info(f"received msg --> {msg}")


if __name__ == '__main__':
    proto = MDB232()
    bill = BillValidator(proto, [1])
    changer = Changer(proto)
    async_reactor()

    embed()
