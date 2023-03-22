from data_types.message import *
from data_types.process_info import *
from .daemon_base import *
import wmi


class ProcessCreationWatcher(Daemon):
    def run(self, ctx: Context, *args):
        logger = self._initLogger(ctx.log_queue)

        w = wmi.WMI()
        watcher = w.watch_for(
            notification_type='creation',
            wmi_class='Win32_Process',
            delay_secs=1)
        logger.debug('Starting up')
        while True:
            try:
                created_process = watcher()
                try:
                    ctx.msg_queue.put(Message(MessageType.NEW_PROCESS, process=WMIProcessInfo(created_process)))
                except Exception as e:
                    logger.warn('Error while pushing message to queue', exc_info=e)
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception as e:
                logger.warn('Error while fetching WMI Event data', exc_info=e)


class ProcessDeletionWatcher(Daemon):
    def run(self, ctx: Context, *args):
        logger = self._initLogger(ctx.log_queue)

        w = wmi.WMI()
        watcher = w.watch_for(
            notification_type='deletion',
            wmi_class='Win32_Process',
            delay_secs=1
        )
        logger.debug('Starting up')
        while True:
            try:
                deleted_process = watcher()
                try:
                    ctx.msg_queue.put(Message(MessageType.DEL_PROCESS, process=WMIProcessInfo(deleted_process)))
                except Exception as e:
                    logger.warn(f'Error while pushing message to queue {e}', exc_info=e)
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception as e:
                logger.warn('Error while fetching WMI Event data', exc_info=e)
