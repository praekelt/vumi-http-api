from twisted.internet.defer import Deferred, succeed


class ConcurrencyLimiterError(Exception):
    """
    Error raised by concurrency limiters.
    """


class ConcurrencyLimiter(object):
    """
    Concurrency limiter.

    Each concurrent operation should call :meth:`start` and wait for the
    deferred it returns to fire before doing any work. When it's done, it
    should call :meth:`stop` to signal completion and allow the next queued
    operation to begin.

    Internally, we track two things:
      * :attr:`_concurrents` holds the number of active operations, for which
        the deferred returned by :meth:`start` has fired, but :meth:`stop` has
        not been called.
      * :attr:`_waiters` holds a list of pending deferreds that have been
        returned by :meth:`start` but not yet fired.
    """

    def __init__(self, name, limit):
        self._name = name
        self._limit = limit
        self._concurrents = 0
        self._waiters = []

    def _inc_concurrent(self):
        self._concurrents += 1
        return self._concurrents

    def _dec_concurrent(self):
        if self._concurrents <= 0:
            raise ConcurrencyLimiterError(
                "Can't decrement key below zero: %s" % (self._name,))
        else:
            self._concurrents -= 1
        return self._concurrents

    def _make_waiter(self):
        d = Deferred()
        self._waiters.append(d)
        return d

    def _pop_waiter(self):
        if not self._waiters:
            return None
        return self._waiters.pop(0)

    def _check_concurrent(self):
        if self._concurrents >= self._limit:
            return
        d = self._pop_waiter()
        if d is not None:
            self._inc_concurrent()
            d.callback(None)

    def empty(self):
        """
        Check if this concurrency limiter is empty so it can be cleaned up.
        """
        return (not self._concurrents) and (not self._waiters)

    def start(self):
        """
        Start a concurrent operation.

        If we are below the limit, we increment the concurrency count and fire
        the deferred we return. If not, we add the deferred to the waiters list
        and return it unfired.
        """
        # While the implemetation matches the description in the docstring
        # conceptually, it always adds a new waiter and then calls
        # _check_concurrent() to handle the various cases.
        if self._limit < 0:
            # Special case for no limit, never block.
            return succeed(None)
        elif self._limit == 0:
            # Special case for limit of zero, always block forever.
            return Deferred()
        d = self._make_waiter()
        self._check_concurrent()
        return d

    def stop(self):
        """
        Stop a concurrent operation.

        If there are waiting operations, we pop and fire the first. If not, we
        decrement the concurrency count.
        """
        # While the implemetation matches the description in the docstring
        # conceptually, it always decrements the concurrency counter and then
        # calls _check_concurrent() to handle the various cases.
        if self._limit <= 0:
            # Special case for where we don't keep state.
            return
        self._dec_concurrent()
        self._check_concurrent()


class ConcurrencyLimitManager(object):
    """
    Concurrency limit manager.

    Each concurrent operation should call :meth:`start` with a key and wait for
    the deferred it returns to fire before doing any work. When it's done, it
    should call :meth:`stop` to signal completion and allow the next queued
    operation to begin.
    """

    def __init__(self, limit):
        self._limit = limit
        self._concurrency_limiters = {}

    def _get_limiter(self, key):
        if key not in self._concurrency_limiters:
            self._concurrency_limiters[key] = ConcurrencyLimiter(
                key, self._limit)
        return self._concurrency_limiters[key]

    def _cleanup_limiter(self, key):
        limiter = self._concurrency_limiters.get(key)
        if limiter and limiter.empty():
            del self._concurrency_limiters[key]

    def start(self, key):
        """
        Start a concurrent operation.

        This gets the concurrency limiter for the given key (creating it if
        necessary) and starts a concurrent operation on it.
        """
        start_d = self._get_limiter(key).start()
        self._cleanup_limiter(key)
        return start_d

    def stop(self, key):
        """
        Stop a concurrent operation.

        This gets the concurrency limiter for the given key (creating it if
        necessary) and stops a concurrent operation on it. If the concurrency
        limiter is empty, it is deleted.
        """
        self._get_limiter(key).stop()
        self._cleanup_limiter(key)
