import argparse
import collections
import fnmatch
import logging
import math
import os
import sys
import threading
import time
import typing

import daemon
import filetype
import psutil
import watchdog
import watchdog.events
import watchdog.observers

FileInfo = collections.namedtuple('FileInfo', 'entropy, mime')


def file_entropy(filepath: str) -> float:
    if not os.path.exists(filepath):
        return 0.0
    file_size = os.stat(filepath).st_size
    with open(filepath, 'rb') as file:
        data = True
        byte_counts = collections.Counter()
        while data:
            data = file.read(4096)
            byte_counts.update(data)
    byte_proportions = [count / file_size for _, count in byte_counts.items()]
    entropy = - sum([proportion * math.log(proportion) / math.log(2.0) for proportion in byte_proportions])
    return abs(entropy / 8)


class FileModEventHandler(watchdog.events.PatternMatchingEventHandler):
    ENTROPY_LIMIT = 0.01
    UNKNOWN_MIME = 'ºunknown'

    def __init__(self, monitoring_path, patterns):
        super().__init__(patterns=patterns, ignore_directories=True)
        self.monitoring_path = monitoring_path
        self.file_infos = self.__init_file_infos()

    def on_created(self, event):
        logging.info(f'"{event.src_path}" created')
        self.file_infos[event.src_path] = FileInfo(file_entropy(event.src_path), self.__get_mime(event.src_path))

    def on_closed(self, event):
        logging.info(f'"{event.src_path}" closed')

    def on_deleted(self, event):
        logging.info(f'"{event.src_path}" deleted')
        if event.src_path not in self.file_infos:
            return
        del self.file_infos[event.src_path]

    def on_modified(self, event):
        logging.info(f'"{event.src_path}" modified')
        self.__update_info(event.src_path)

    def on_moved(self, event):
        logging.info(f'"{event.src_path}" moved to "{event.dest_path}"')
        if event.src_path in self.file_infos:
            self.file_infos[event.dest_path] = self.file_infos[event.src_path]
            del self.file_infos[event.src_path]
            self.__update_info(event.dest_path)
        else:
            self.file_infos[event.dest_path] = FileInfo(file_entropy(event.dest_path), self.__get_mime(event.dest_path))

    def __update_info(self, filepath: str) -> None:
        if filepath not in self.file_infos:
            return
        if not os.path.exists(filepath):
            del self.file_infos[filepath]
            return
        new_entropy = file_entropy(filepath)
        new_mime = self.__get_mime(filepath)
        entropy_diff = new_entropy - self.file_infos[filepath].entropy
        if entropy_diff > self.ENTROPY_LIMIT:
            logging.warning(f'"{filepath}" has increased its entropy by {entropy_diff * 100:.2f}%')
        if new_mime != self.file_infos[filepath].mime:
            logging.warning(f'"{filepath}" has changed its MIME: {self.file_infos[filepath].mime} → {new_mime}')
        self.file_infos[filepath] = FileInfo(new_entropy, new_mime)

    def __init_file_infos(self) -> typing.Dict[str, FileInfo]:
        result = dict()
        for root_path, folders, files in os.walk(self.monitoring_path):
            for pattern in self.patterns:
                filtered_files = fnmatch.filter(files, pattern)
                for file in filtered_files:
                    filepath = os.path.join(root_path, file)
                    result[filepath] = FileInfo(file_entropy(filepath), self.__get_mime(filepath))
        return result

    @staticmethod
    def __get_mime(filepath: str) -> str:
        file_type = filetype.guess(filepath)
        if file_type:
            return file_type.mime
        return '<unknown>'


class IronDome:
    LOG_FILEPATH = '/var/log/irondome/irondome.log'
    SLEEP_TIME = 5

    def __init__(self, dir_path='.', patterns: list = None, interval: int = 1):
        self.monitoring_path = os.path.abspath(os.path.expanduser(dir_path))
        if patterns:
            self.patterns = list(map(lambda x: f'*.{x}', patterns))
        else:
            self.patterns = ['*']
        if os.path.isfile(self.monitoring_path):
            self.monitoring_path, filename = os.path.split(self.monitoring_path)
            self.patterns = [filename]
        self.interval = interval
        self.cpu_thread = threading.Thread(target=self.__cpu_check)
        self.mem_thread = threading.Thread(target=self.__mem_check)
        self.disk_thread = threading.Thread(target=self.__disk_check)

    def run(self):
        self.cpu_thread.start()
        self.mem_thread.start()
        self.disk_thread.start()
        os.makedirs(os.path.split(self.LOG_FILEPATH)[0], exist_ok=True)
        logging.basicConfig(filename=self.LOG_FILEPATH,
                            filemode='a',
                            level=logging.INFO,
                            format='%(asctime)s - %(levelname)s: %(message)s',
                            datefmt='%Y-%m-%d %H:%M:%S')
        event_handler = FileModEventHandler(self.monitoring_path, self.patterns)
        observer = watchdog.observers.Observer()
        observer.schedule(event_handler, self.monitoring_path, recursive=os.path.isdir(self.monitoring_path))
        observer.start()
        try:
            while True:
                time.sleep(self.SLEEP_TIME)
        finally:
            observer.stop()
            observer.join()

    @staticmethod
    def __cpu_check():
        while True:
            cpu = psutil.cpu_percent(interval=1)
            if cpu > 10:
                logging.warning('intensive use of cpu (cryptography activity)')
                time.sleep(10)

    @staticmethod
    def __mem_check():
        while True:
            mem = psutil.Process().memory_info().rss / 1048576
            if mem > 100:
                logging.error('memory exceed the 100MB limit')
            time.sleep(10)

    @staticmethod
    def __disk_check():
        sleep_time = 1
        last_reading_time = IronDome.__reading_time()
        while True:
            new_reading_time = IronDome.__reading_time()
            reading_time_diff = new_reading_time - last_reading_time
            if reading_time_diff > sleep_time * 100:
                logging.warning('intensive disk read')
            last_reading_time = new_reading_time
            time.sleep(sleep_time)

    @staticmethod
    def __reading_time():
        with open('/proc/diskstats') as f:
            time_ms = f.readline().split()[6]
            if time_ms.isdecimal():
                return int(time_ms)
            return 0


def get_args():
    parser = argparse.ArgumentParser(
        prog='Iron Dome',
        description='This program will monitor a critical zone in perpetuity.',
    )
    parser.add_argument('route', type=str, metavar='ROUTE')
    parser.add_argument('extensions', type=str, nargs='*', metavar='FILE_EXTENSION')
    parser.add_argument('-i', '--interval', type=int, default=1)
    return parser.parse_args()


if __name__ == "__main__":
    if os.getuid() != 0:
        print('Warning: User is not root')
        exit(1)
    args = get_args()
    dome = IronDome(args.route, args.extensions, args.interval)
    with daemon.DaemonContext(stdout=sys.stdout, stderr=sys.stderr):
        print(f'PID:{os.getpid()}')
        dome.run()
