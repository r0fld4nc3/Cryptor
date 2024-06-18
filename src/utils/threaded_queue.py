import queue
import threading

from src.logs import create_logger
from conf_globals.globals import G_LOG_LEVEL

log = create_logger("Threaded Queue", G_LOG_LEVEL)

class ThreadedQueue:
    def __init__(self, num_workers: int=2):
        self._task_queue: queue = queue.Queue()
        # self._results_queue = queue.Queue()
        if num_workers < 1:
            num_workers = 2
        self._num_workers: int = num_workers
        self._workers: list = []
        self._total_jobs = 0
        self._completed_jobs = 0
        self._stopped = True

        log.info(f"Init with {self._workers} workers")

    @property
    def task_queue(self):
        return self._task_queue

    # @property
    # def results_queue(self):
    #     return self._results_queue

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

    @property
    def empty(self) -> bool:
        return self._task_queue.qsize() == 0

    @property
    def task_queue_size(self) -> int:
        return self._task_queue.qsize()

    # @property
    # def results_queue_size(self) -> int:
    #     return self._results_queue.qsize()

    @property
    def completed_jobs(self):
        return self._completed_jobs

    @property
    def jobs_finished(self) -> bool:
        return (self.empty and (self._completed_jobs >= self._total_jobs)) or self._stopped

    def start_workers(self):
        log.info("Starting workers")

        self._stopped = False
        for _ in range(self._num_workers):
            log.debug(f"threading.Thread(target={self.worker_function})")
            worker = threading.Thread(target=self.worker_function)
            worker.start()
            log.debug(f"self.workers.append({worker})")
            self._workers.append(worker)

    def worker_function(self):
        while not self._stopped:
            log.debug("Checking for tasks")

            # Blocks until a task becomes available
            task = self._task_queue.get()

            if isinstance(task, tuple):
                func, args, kwargs = task
                try:
                    result = func(*args, **kwargs)
                except Exception as e:
                    if e is None:
                        log.warning(f"{e}\n {' ' * 45}{'^' * len(str(e))}")
                    result = e
            elif task is None:
                # Exit gracefully
                # self._results_queue.put(result)
                self._task_queue.task_done()
                break
            else:
                log.warning(f"Task of else: {task}")

            # self._results_queue.put(result)
            self._task_queue.task_done()
            self._completed_jobs += 1

    def add_task(self, func, *args, **kwargs):
        log.info(f"Adding task: {func}, {args}, {kwargs}")
        self._task_queue.put((func, args, kwargs))
        self._total_jobs += 1

    def stop_workers(self):
        log.info(f"Stopping workers ({self._num_workers})")

        self._stopped = True

        for _ in range(self._num_workers):
            log.info("Stopping")
            self.add_task(None)
