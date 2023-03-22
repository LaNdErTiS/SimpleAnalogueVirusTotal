import json

from daemons.wmi_daemons import *
from daemons.connection_listener_daemon import *
from daemons.memory_checker_pool import *
from daemons.static_checker_pool import *
from daemons.dumper_daemon import *
from logging.handlers import QueueListener
import multiprocessing
import os
import logging
import time
import datetime
import argparse

MAX_QUEUE_SIZE = 100
MAX_MEMORY_TASK_COUNT = 100
POOL_SIZE = 2


def logger_init(q):
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter('(%(name)s)\t[%(levelname)s]\t%(message)s'))

    ql = QueueListener(q, handler)
    ql.start()

    logger = logging.getLogger()
    logger.setLevel(logging.CRITICAL)
    logger.addHandler(handler)

    return ql, q


ctx: Context = None
manager: multiprocessing.Manager = None


def process_explorer_main(results_path):
    print('[>] Initializing watcher systems')

    global ctx, manager
    ctx = Context()
    manager = multiprocessing.Manager()

    ql, q = logger_init(manager.Queue())

    ctx.msg_queue = manager.Queue(maxsize=MAX_QUEUE_SIZE)
    ctx.log_queue = q
    ctx.memory_task_queue = manager.Queue(maxsize=MAX_MEMORY_TASK_COUNT)
    ctx.tracking_pids = manager.list([])
    ctx.process_infos = manager.dict({})

    watchers = [ProcessCreationWatcher, ProcessDeletionWatcher, ConnectionListener]
    watchers_procs = []
    own_pids = [os.getpid()]

    logging.debug('Spawning watchers')
    for watcher in watchers:
        p = daemonize(watcher(), (ctx,))
        p.start()
        own_pids.append(p.pid)
        watchers_procs.append(p)

    p = daemonize(JSONDumper(), (ctx, results_path))
    p.start()
    own_pids.append(p.pid)
    watchers_procs.append(p)

    logging.debug(f'Self pids = {own_pids}')

    logging.debug(f'Spawning memory watcher pool')
    memory_watchers = MemoryValidatorPool(POOL_SIZE, ctx)
    static_checkers = StaticCheckerPool(POOL_SIZE, ctx)

    print('[>] Starting watcher systems')
    logging.info(f'Starting watchers')
    time.sleep(1)
    print('[>] Ready to go!')

    try:
        while True:
            if not ctx.msg_queue.empty():
                msg: Message = ctx.msg_queue.get()
                if msg.type == MessageType.NEW_PROCESS:
                    proc: WMIProcessInfo = msg.process
                    if proc.ProcessId in own_pids:
                        continue

                    logging.info(f'Discovered new process - [{proc.ProcessId}] - {proc.Name} - {proc.CommandLine}')

                    print(f'[>] Tracking new process - [{proc.ProcessId}] - {proc.Name}')

                    proc_info: ProcessInformation = ProcessInformation()
                    proc_info.init(proc)
                    proc_info.connections = manager.list([])
                    proc_info.memory = manager.list([])

                    proc_info.packer = manager.list([])
                    proc_info.signature_verification = manager.list([])
                    proc_info.section_rights = manager.list([])
                    proc_info.mitre_techniques = manager.list([])

                    ctx.process_infos[proc_info.pid] = proc_info

                    static_checkers.sch_find_packer(ctx, proc_info.pid)
                    static_checkers.sch_find_signature(ctx, proc_info.pid)
                    static_checkers.sch_find_sections(ctx, proc_info.pid)
                    static_checkers.sch_find_mitre(ctx, proc_info.pid)
                    ctx.tracking_pids.append(proc_info.pid)

                    ctx.memory_task_queue.put(proc_info.pid)
                elif msg.type == MessageType.DEL_PROCESS:
                    proc: WMIProcessInfo = msg.process
                    if proc.ProcessId in own_pids:
                        continue

                    logging.info(f'Process exited - [{proc.ProcessId}] - {proc.Name}')
                    if proc.ProcessId in ctx.process_infos:
                        del ctx.process_infos[proc.ProcessId]

                elif msg.type == MessageType.NEW_CONNECTION:
                    conn: ConnectionInfo = msg.conninfo
                    if conn.pid in ctx.process_infos.keys():
                        conn.retrieve_info()
                        logging.info(f'New connection - {conn}')
                        ctx.process_infos[conn.pid].connections.append(conn)
                        if conn.abuseScore and conn.abuseScore > 50:
                            print(
                                f'[!] Process {conn.pid} ({ctx.process_infos[conn.pid].name}) made connection to malicious IP: {conn}')

                elif msg.type == MessageType.MEMORY_CHECK_PERFORMED:
                    pid: int = msg.pid
                    pickled_result = msg.result
                    if not pickled_result:
                        continue

                    if pid in ctx.process_infos.keys():
                        ctx.process_infos[pid].memory[:] = []
                        ctx.process_infos[pid].memory[:] = [pickled_result]
                        logging.debug(f'[{pid}] Got new memory check result')

                elif msg.type == MessageType.CHK_PACKER_RESULT:
                    pid: int = msg.pid
                    packer = msg.packer
                    if not packer:
                        continue
                    if pid in ctx.process_infos.keys():
                        ctx.process_infos[pid].packer[:] = []
                        ctx.process_infos[pid].packer[:] = [packer]

                elif msg.type == MessageType.CHK_SIGNATURE_RESULT:
                    pid: int = msg.pid
                    sig = msg.signature
                    if not sig:
                        continue

                    if pid in ctx.process_infos.keys():
                        ctx.process_infos[pid].signature_verification[:] = []
                        ctx.process_infos[pid].signature_verification[:] = [sig]

                elif msg.type == MessageType.CHK_SECTIONS_RESULT:
                    pid: int = msg.pid
                    sections = msg.sections
                    if not sections:
                        continue

                    if pid in ctx.process_infos.keys():
                        ctx.process_infos[pid].section_rights[:] = []
                        ctx.process_infos[pid].section_rights[:] = [sections]

                elif msg.type == MessageType.CHK_MITRE:
                    pid: int = msg.pid
                    mitre = msg.mitre
                    if not mitre:
                        continue

                    if pid in ctx.process_infos.keys():
                        ctx.process_infos[pid].mitre_techniques[:] = []
                        ctx.process_infos[pid].mitre_techniques[:] = [mitre]

    except (KeyboardInterrupt, SystemExit) as E:
        logging.info(f'Shutting down')
        print('[>] Exitting...')
        for watcher in watchers_procs:
            if type(watcher) == JSONDumper:
                watcher.dump()
            watcher.terminate()

        del memory_watchers
        ql.stop()


def get_reason_description(reason: dict, proc_data: dict):
    if 'reason' not in reason.keys():
        return '<error>'

    if reason['reason'] == 'malicious_packer':
        return f'Executable has malicious packer - {reason["data"]}'

    if reason['reason'] == 'bad_signature':
        return f'Executable has invalid signature - {reason["data"]}'

    if reason['reason'] == 'malicious_section_rights':
        return f"Executable has {len(reason['data'])} sections with malicious rights - {reason['data']}"

    if reason['reason'] == 'malicious_connection':
        conn_data = f"{reason['data']['to']} ({reason['data']['domain']}) [{reason['data']['country']},isp={reason['data']['isp']},SCORE={reason['data']['abuseScore']}]"
        return f"Process made very suspicious connect to {conn_data}"

    if reason['reason'] == 'bad_sections_data':
        sections_data = []
        for section in reason['data']:
            if section['reason'] == 'high_size_diff':
                sections_data.append(f"Section {section['section']} has bad in-memory size")
            if section['reason'] == 'unmatching_bytes':
                sections_data.append(f"Section {section['section']} has unmatching bytes in memory")
        return f"Process has suspicious section data:\n" + '\t\t' + '\n\t\t'.join(sections_data)

    if reason['reason'] == 'mitre_techniques':
        mitre_techs = [f"{x} - {list(proc_data['mitre_techniques'][x].keys())[0]}" for x in proc_data['mitre_techniques'].keys()]
        return f"Process using some MITRE ATT&CK techniques:\n" + "\t\t" + '\n\t\t'.join(mitre_techs)


def score_parser_main(result_dir, process_count):
    full_dir_path = os.path.join('results', result_dir)
    print(f'[>] Performing score checking on results {result_dir} (path = {full_dir_path})')
    if not os.path.exists(full_dir_path):
        print(f'[!] Cannot read results from {result_dir} - it does not exist')
        return

    result_files = [file for _, _, files in os.walk(full_dir_path) for file in files]
    print(f'[>] Found {len(result_files)} files to check')
    results = []
    for result_file in result_files:
        with open(os.path.join(full_dir_path, result_file), 'r') as f:
            result = f.read()
        json_result = json.loads(result)
        results.append(json_result)

    print(f'[>] Analyzing loaded results')
    bad_results = sorted(results, key=lambda r: r['score']['total_score'], reverse=True)[:process_count]
    bad_results = list(filter(lambda r: r['score']['total_score'] > 0, bad_results))
    if len(bad_results) == 0:
        print(f'[!] There is no processes with score higher than 0')
        return

    print(f'[>] Showing {len(bad_results)} processes')
    for res in bad_results:
        print(f'[{"-" * 20}]')
        print(f"[|] Process name: {res['name']}")
        print(f"[|] PID: {res['pid']}")
        print(f"[|] Arguments: {res['cmd_line']}")
        print(f"[|] TOTAL SCORE: {res['score']['total_score']}")
        if res['score']['total_score'] != 0:
            for reason in res['score']['reasons']:
                print(f"[|]\t+{reason['score_impact']} - {get_reason_description(reason, res)}")
        print(f'[{"-" * 20}]')
        print()


def main():
    parser = argparse.ArgumentParser(prog='process-explorer')
    parser.add_argument('-n', '--no-watcher', action='store_true', default=False,
                        help='if provided, only existing results will be parsed')
    parser.add_argument('-d', '--dir', action='store', default=None, help='parse results from this directory')
    parser.add_argument('-N', '--number', action='store', default=5, type=int, help='count of processes to show')
    args = parser.parse_args()

    if args.no_watcher and not args.dir:
        print('[ERR] Provide directory to parse')
        return

    result_dir = f'{datetime.datetime.now().strftime("%d-%m-%Y_%H-%M-%S")}'
    result_dir_path = f'results\\{result_dir}'
    if not args.no_watcher:
        process_explorer_main(result_dir_path)
    if args.dir:
        score_parser_main(args.dir, args.number)
    else:
        score_parser_main(result_dir, args.number)


if __name__ == '__main__':
    main()
