import pickle
import time

from .daemon_base import *
from data_types.message import *
import memory.memoryvalidator as validator


def memory_checker_main(ctx: Context):
    while True:
        pid = ctx.memory_task_queue.get(True)
        result = validator.validator_main(pid, ctx)
        ctx.msg_queue.put(Message(MessageType.MEMORY_CHECK_PERFORMED, pid=pid, result=pickle.dumps(result)))
        time.sleep(2)
        if pid in ctx.process_infos.keys():
            ctx.memory_task_queue.put(pid)


class MemoryValidatorPool:
    def __init__(self, pool_size, ctx: Context):
        self.pool = multiprocessing.Pool(pool_size, memory_checker_main, (ctx,))

    def __del__(self):
        self.pool.terminate()
