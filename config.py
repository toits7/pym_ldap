import os
import logging
import datetime
import sys
from pym_ldap import set_domain, LdapDomain


app_log_folder = "logs"
log_format = f"%(asctime)s - [%(levelname)s] - %(name)s - (%(filename)s).%(funcName)s(%(lineno)d) " \
             f"- %(message)s"
console_log_level = logging.INFO
file_log_level = logging.DEBUG
log_file_name = datetime.datetime.now().strftime("%d-%m-%Y") + '.log'
log_folder_path = app_log_folder
if "debug" in sys.argv:
    log_level = logging.DEBUG
else:
    log_level = logging.INFO


def get_file_handler():
    file_path = os.path.join(log_folder_path, log_file_name)
    file_handler = logging.FileHandler(file_path, encoding="utf-8")
    file_handler.setLevel(file_log_level)
    return file_handler


def get_stream_handler():
    stream_handler = logging.StreamHandler()
    stream_handler.setLevel(console_log_level)
    return stream_handler


logging.basicConfig(level=log_level, format=log_format, handlers=[get_stream_handler(), get_file_handler()])
set_domain(LdapDomain.load_from_json("domain.json"))
