from .daemon_base import *
from data_types.message import *
from data_types.connection_info import *
import psutil


class ConnectionListener(Daemon):
    def run(self, ctx: Context, *args):
        logger = self._initLogger(ctx.log_queue)

        conns = frozenset(psutil.net_connections())
        while True:
            curr = frozenset(psutil.net_connections())
            diff = curr.difference(conns)
            for conn in diff:
                ctx.msg_queue.put(Message(MessageType.NEW_CONNECTION,
                                          conninfo=ConnectionInfo(conn)))
            conns = curr
