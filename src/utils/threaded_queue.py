import queue
import threading

from src.logs.cryptor_logger import create_logger
from conf_globals.globals import G_THREAD_NUM_WORKERS, G_LOG_LEVEL

threadlogger = create_logger("ThreadLogger", G_LOG_LEVEL)

class ThreadedQueue:
    def __init__(self, num_workers: int=G_THREAD_NUM_WORKERS):
        self._task_queue: queue = queue.Queue()
        self._results_queue = queue.Queue()
        self._num_workers: int = num_workers
        self._workers: list = []
        self._total_jobs = 0

        threadlogger.info(f"Init with {self._workers} workers")

    @property
    def task_queue(self):
        return self._task_queue

    @property
    def results_queue(self):
        return self._results_queue

    @property
    def num_workers(self):
        return self._num_workers

    @num_workers.setter
    def num_workers(self, num: int):
        if num > 0:
            self._num_workers = num
        else:
            self._num_workers = 2

    @property
    def workers(self):
        return self._workers

    @property
    def jobs(self):
        return self._total_jobs

    def start_workers(self):
        threadlogger.info("Starting workers")
        for _ in range(self._num_workers):
            threadlogger.debug(f"threading.Thread(target={self.worker_function})")
            worker = threading.Thread(target=self.worker_function)
            worker.start()
            threadlogger.debug(f"self.workers.append({worker})")
            self._workers.append(worker)

    def worker_function(self):
        while True:
            threadlogger.debug("Checking")
            # Blocks until a task becomes available
            task = self._task_queue.get()
            if task is None:
                break
            if isinstance(task, tuple):
                func, args, kwargs = task
                try:
                    result = func(*args, **kwargs)
                    if result is None:
                        result = False
                    self._task_queue.task_done()
                except Exception as e:
                    if e is None:
                        threadlogger.error(f"{e}\n {' '*45}{'^'*len(str(e))} Could likely be ignored, normal shutown behaviour")
                    result = e
                self._task_queue.put(result)
                self._results_queue.put(result)
            else:
                # Exit gracefully
                self._task_queue.put(None)

    def add_task(self, func, *args, **kwargs):
        threadlogger.info(f"Adding task: {func}, {args}, {kwargs}")
        self._task_queue.put((func, args, kwargs))
        self._total_jobs += 1

    def stop_workers(self):
        threadlogger.info(f"Stopping workers ({self._num_workers})")
        for _ in range(self._num_workers):
            threadlogger.info("Stopping")
            self.add_task(None)

    @staticmethod
    def new_queue() -> queue.Queue:
        return queue.Queue()

    def empty(self) -> bool:
        return self._task_queue.qsize() == 0

    def results_queue_size(self) -> int:
        return self._results_queue.qsize()

    def jobs_finished(self) -> bool:
        return self.empty() and self.results_queue_size() == self._total_jobs

    def restart_counts(self):
        self._task_queue: queue = queue.Queue()
        self._results_queue = queue.Queue()
        self._workers: list = []
        self._total_jobs = 0
