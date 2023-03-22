import multiprocessing
import logging
from logging.handlers import QueueHandler


class Context:
    msg_queue: multiprocessing.Queue
    log_queue: multiprocessing.Queue
    memory_task_queue: multiprocessing.Queue
    tracking_pids = []
    process_infos = {}


def initMultiprocessingLogger(q: multiprocessing.Queue, name: str):
    qh = QueueHandler(q)
    logger = logging.getLogger(name)
    logger.setLevel(logging.CRITICAL)
    logger.addHandler(qh)
    return logger


class Daemon:
    def run(self, ctx, *args):
        raise NotImplementedError

    def _initLogger(self, q: multiprocessing.Queue):
        return initMultiprocessingLogger(q, type(self).__name__)


def run_daemon(daemon: Daemon, daemon_context: Context, *args):
    daemon.run(daemon_context, *args)


def daemonize(daemon: Daemon, args: tuple) -> multiprocessing.Process:
    p = multiprocessing.Process(target=run_daemon, args=(daemon, *args))
    p.daemon = True
    return p
