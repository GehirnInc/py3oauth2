# -*- coding: utf-8 -*-

import enum
import string
import random


class RSFlag(enum.IntEnum):
    LOWER = 1
    UPPER = 1 << 1
    DIGITS = 1 << 2


def generate_random_string(length, flag):
    kinds = []

    if flag & RSFlag.LOWER > 0:
        kinds.append(string.ascii_lowercase)

    if flag & RSFlag.UPPER > 0:
        kinds.append(string.ascii_uppercase)

    if flag & RSFlag.DIGITS:
        kinds.append(string.digits)

    pool = ''.join(kinds)
    return ''.join(random.choice(pool) for _ in range(length))
