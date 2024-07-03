#!/usr/bin/env python3

from random import choice
from string import ascii_uppercase, digits
from time import sleep
from random import randint


def gen_flag():
    alphabet = ascii_uppercase + digits
    return "".join(choice(alphabet) for _ in range(31)) + "="

a = randint(0, 3)
if a == 0:
    print(f"Generating random flag: {gen_flag()}", flush=True)
elif a == 1:
    exit(-1)
else:
    print("ciaoh")
