from data_types.process_info import *
import os
import json


def dump_info(pinfo: ProcessInformation, result_dir):
    FILE_FORMAT = '{name}-{pid}.txt'
    with open(os.path.join(result_dir, FILE_FORMAT.format(name=pinfo.name, pid=pinfo.pid)), 'w') as f:
        json.dump(pinfo.json(), f, indent=4)


def dump_all(proc_infos: dict[int, ProcessInformation], result_dir='results'):
    res_dir_fullpath = os.path.join(os.getcwd(), result_dir)
    if not os.path.exists(res_dir_fullpath):
        os.mkdir(res_dir_fullpath)
    for pinfo in proc_infos.keys():
        try:
            dump_info(proc_infos[pinfo], res_dir_fullpath)
        except Exception as E:
            pass
