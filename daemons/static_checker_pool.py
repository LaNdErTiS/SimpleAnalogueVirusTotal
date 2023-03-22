from .daemon_base import *
from data_types.message import *
from data_types.process_info import *
from mitre.mitre import *

import pe_check


def get_path(ctx: Context, pid):
    if pid not in ctx.process_infos.keys():
        return None

    info: ProcessInformation = ctx.process_infos[pid]
    if not info.exe_path:
        return None

    return info.exe_path


def chk_get_packer(ctx: Context, pid):
    path = get_path(ctx, pid)
    if not path:
        return False

    result = ','.join(pe_check.get_packer(path)[0][1])
    ctx.msg_queue.put(Message(MessageType.CHK_PACKER_RESULT, pid=pid, packer=result))
    return True


def chk_get_signature(ctx: Context, pid):
    path = get_path(ctx, pid)
    if not path:
        return False

    result = pe_check.get_pe_file_signature(path)
    ctx.msg_queue.put(Message(MessageType.CHK_SIGNATURE_RESULT, pid=pid, signature=result))
    return True


def chk_get_sections(ctx: Context, pid):
    path = get_path(ctx, pid)
    if not path:
        return False

    result = pickle.dumps(pe_check.get_sections_attributes(path))
    ctx.msg_queue.put(Message(MessageType.CHK_SECTIONS_RESULT, pid=pid, sections=result))
    return True


def chk_get_mitre(ctx: Context, pid):
    path = get_path(ctx, pid)
    if not path:
        return False

    result = pickle.dumps(get_mitre_techniques(path))
    ctx.msg_queue.put(Message(MessageType.CHK_MITRE, pid=pid, mitre=result))
    return True


class StaticCheckerPool:
    def __init__(self, pool_size, ctx: Context):
        self.pool = multiprocessing.Pool(pool_size)

    def sch_find_packer(self, ctx, pid):
        r = self.pool.apply_async(func=chk_get_packer, args=(ctx, pid))
        try:
            r.get(0.01)
        except multiprocessing.TimeoutError:
            pass

    def sch_find_signature(self, ctx, pid):
        r = self.pool.apply_async(func=chk_get_signature, args=(ctx, pid))
        try:
            r.get(0.01)
        except multiprocessing.TimeoutError:
            pass

    def sch_find_sections(self, ctx, pid):
        r = self.pool.apply_async(func=chk_get_sections, args=(ctx, pid))
        try:
            r.get(0.01)
        except multiprocessing.TimeoutError:
            pass

    def sch_find_mitre(self, ctx, pid):
        r = self.pool.apply_async(func=chk_get_mitre, args=(ctx, pid))
        try:
            r.get(0.01)
        except multiprocessing.TimeoutError:
            pass
