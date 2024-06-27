#!/usr/bin/env python3

from random import choice
from string import ascii_uppercase, digits


def gen_flag():
    alphabet = ascii_uppercase + digits
    return "".join(choice(alphabet) for _ in range(31)) + "="


print(f"Generating random flag: {gen_flag()}", flush=True)
