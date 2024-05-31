import queue
import threading

from src.logs.cryptor_logger import create_logger
from conf_globals.globals import G_THREAD_NUM_WORKERS, G_LOG_LEVEL

threadlogger = create_logger("ThreadLogger", G_LOG_LEVEL)

class ThreadedQueue:
    def __init__(self, num_workers: int=G_THREAD_NUM_WORKERS):
        self.task_queue: queue = queue.Queue()
        self.results_queue = queue.Queue()
        self.num_workers: int = num_workers
        self.workers: list = []
        self.total_jobs = 0

        threadlogger.info(f"Init with {self.workers} workers")

    def start_workers(self):
        threadlogger.info("Starting workers")
        for _ in range(self.num_workers):
            threadlogger.debug(f"threading.Thread(target={self.worker_function})")
            worker = threading.Thread(target=self.worker_function)
            worker.start()
            threadlogger.debug(f"self.workers.append({worker})")
            self.workers.append(worker)

    def worker_function(self):
        while True:
            threadlogger.debug("Checking")
            # Blocks until a task becomes available
            task = self.task_queue.get()
            if task is None:
                break
            if isinstance(task, tuple):
                func, args, kwargs = task
                try:
                    result = func(*args, **kwargs)
                    if result is None:
                        result = False
                    self.task_queue.task_done()
                except Exception as e:
                    if e is None:
                        threadlogger.error(f"{e}\n {' '*45}{'^'*len(str(e))} Could likely be ignored, normal shutown behaviour")
                    result = e
                self.task_queue.put(result)
                self.results_queue.put(result)
            else:
                # Exit gracefully
                self.task_queue.put(None)

    def add_task(self, func, *args, **kwargs):
        threadlogger.info(f"Adding task: {func}, {args}, {kwargs}")
        self.task_queue.put((func, args, kwargs))
        self.total_jobs += 1

    def stop_workers(self):
        threadlogger.info(f"Stopping workers ({self.num_workers})")
        for _ in range(self.num_workers):
            threadlogger.info("Stopping")
            self.add_task(None)

    def new_queue(self) -> queue.Queue:
        return queue.Queue()

    def empty(self) -> bool:
        return self.task_queue.empty()

    def results_queue_size(self) -> int:
        return self.results_queue.qsize()

    def jobs_finished(self) -> bool:
        return self.empty() and self.results_queue_size() == self.total_jobs
