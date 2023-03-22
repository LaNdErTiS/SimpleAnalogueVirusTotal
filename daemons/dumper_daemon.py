from .daemon_base import *
import time
import result_dumper


class JSONDumper(Daemon):

    def __init__(self):
        self.result_dir = None
        self.ctx = None

    def dump(self):
        result_dumper.dump_all(self.ctx.process_infos, result_dir=self.result_dir)

    def run(self, ctx: Context, *args):
        logger = self._initLogger(ctx.log_queue)
        result_dir = 'results'
        if args:
            result_dir = args[0]

        self.ctx = ctx
        self.result_dir = result_dir

        while True:
            try:
                time.sleep(5)
                logger.info('Dumping infos')
                self.dump()
            except (KeyboardInterrupt, SystemExit) as E:
                break
