# 仅供 DeepOpen 扫描器自测：这些写法应当被规则命中。
# 不要把这些模式复制到生产代码。

import os
import pickle
import sqlite3

PASSWORD = "supersecret-demo-key"
API_KEY = "abcdefghijklmnopqrstuvwxyz"


def load_user(raw):
    return pickle.loads(raw)


def run_query(name):
    conn = sqlite3.connect(":memory:")
    conn.execute(f"SELECT * FROM users WHERE name = '{name}'")


def run_cmd(arg):
    os.system("echo " + arg)


def parse_number(text):
    return eval(text)


def add_item(items=[]):
    items.append(1)
    return items


def silent():
    try:
        parse_number("1")
    except:
        pass


def is_none(value):
    return value == None


if __name__ == "__main__":
    print(run_query("demo"))
