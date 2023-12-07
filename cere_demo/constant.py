# -*- coding: utf-8 -*-
from dataclasses import dataclass, field
from enum import IntEnum, Enum, auto

ESCROW_STATUS_RETURN_BILL = b'\x00'
ESCROW_STATUS_STACK_BILL = b'\x01'

RESP_BILL_DISABLED = b"\x30\x09"  # 纸币机被禁止时会一直上报

BILL_ADDR = b"\x30"   # 纸币机 地址
CHANGER_ADDR = b"\x08" # 硬币机 地址


@dataclass
class ST:
    code: int
    name: str
    note: str


# 纸币路径
BILL_ROUTE_STACKED = 0
BILL_ROUTE_ESCROW_POS = 1
BILL_ROUTE_RETURNED = 2
BILL_ROUTE_UNUSED = 3
BILL_ROUTE_REJECTED = 4

# BILL_ROUTE_TO_RECYCLER_MANUAL = 5
# BILL_ROUTE_DISPENSE_MANUAL = 6
# BILL_ROUTE_FROM_RECYCLER_TO_CASHBOX = 7


BILL_ROUTING = {
    BILL_ROUTE_STACKED: ST(BILL_ROUTE_STACKED, "bill_route_stacked", "钱币进入钱箱"),
    BILL_ROUTE_ESCROW_POS: ST(BILL_ROUTE_ESCROW_POS, "bill_route_escrow_pos", "钱币进入暂存"),
    BILL_ROUTE_RETURNED: ST(BILL_ROUTE_RETURNED, "bill_route_returned", "纸币被退回"),
    BILL_ROUTE_UNUSED: ST(BILL_ROUTE_UNUSED, "bill_route_unused", "未使用"),
    BILL_ROUTE_REJECTED: ST(BILL_ROUTE_REJECTED, "bill_route_rejected", "钱币因被禁止而拒收")
}

# 纸币机状况
STATUS_DEFECTIVE_MOTOR = 1
STATUS_SENSOR_PROBLEM = 2
STATUS_VALIDATOR_BUSY = 3
STATUS_ROM_CHECKSUM_ERROR = 4
STATUS_VALIDATOR_JAMMED = 5
STATUS_VALIDATOR_RESET = 6
STATUS_BILL_REMOVED = 7
STATUS_CASH_BOX_OUT_OF_POSITION = 8
STATUS_VALIDATOR_DISABLED = 9
STATUS_INVALID_ESCROW_REQUEST = 0xA
STATUS_BILL_REJECTED = 0xB
# 无效的纸币: 010xxxxx

BILL_ST = {
    STATUS_DEFECTIVE_MOTOR: ST(STATUS_DEFECTIVE_MOTOR, "status_defective_motor", "电机故障"),
    STATUS_SENSOR_PROBLEM: ST(STATUS_SENSOR_PROBLEM, "status_sensitive_motor", "感应器故障"),
    STATUS_VALIDATOR_BUSY: ST(STATUS_VALIDATOR_BUSY, "status_validator_busy", "纸币机忙"),
    STATUS_ROM_CHECKSUM_ERROR: ST(STATUS_ROM_CHECKSUM_ERROR, "status_rom_checksum_error", "ROM校验和错误"),
    STATUS_VALIDATOR_JAMMED: ST(STATUS_VALIDATOR_JAMMED, "status_validator_jammed", "纸币机卡币"),
    STATUS_VALIDATOR_RESET: ST(STATUS_VALIDATOR_RESET, "status_validator_reset", "纸币机复位"),
    STATUS_BILL_REMOVED: ST(STATUS_BILL_REMOVED, "status_bill_removed", "纸币被拿走"),
    STATUS_CASH_BOX_OUT_OF_POSITION: ST(STATUS_CASH_BOX_OUT_OF_POSITION, "status_cash_box_out_of_position", "纸箱不在原位"),
    STATUS_VALIDATOR_DISABLED: ST(STATUS_VALIDATOR_DISABLED, "status_validator_disabled", "纸币器被禁止"),
    STATUS_INVALID_ESCROW_REQUEST: ST(STATUS_INVALID_ESCROW_REQUEST, "status_invalid_escrow_request", "暂存要求无效"),
    STATUS_BILL_REJECTED: ST(STATUS_BILL_REJECTED, "status_bill_rejected", "纸币被退出")

}

