from vumi.tests.helpers import VumiTestCase

from ..concurrency_limiter import (
    ConcurrencyLimitManager, ConcurrencyLimiterError)


class TestConcurrencyLimitManager(VumiTestCase):
    def test_concurrency_limiter_no_limit(self):
        """
        When given a negitive limit, ConcurrencyLimitManager never blocks.
        """
        limiter = ConcurrencyLimitManager(-1)
        d1 = limiter.start("key")
        self.assertEqual(d1.called, True)
        d2 = limiter.start("key")
        self.assertEqual(d2.called, True)

        # Check that we aren't storing any state.
        self.assertEqual(limiter._concurrency_limiters, {})

        # Check that stopping doesn't explode.
        limiter.stop("key")

    def test_concurrency_limiter_zero_limit(self):
        """
        When given a limit of zero, ConcurrencyLimitManager always blocks
        forever.
        """
        limiter = ConcurrencyLimitManager(0)
        d1 = limiter.start("key")
        self.assertEqual(d1.called, False)
        d2 = limiter.start("key")
        self.assertEqual(d2.called, False)

        # Check that we aren't storing any state.
        self.assertEqual(limiter._concurrency_limiters, {})

        # Check that stopping doesn't explode.
        limiter.stop("key")

    def test_concurrency_limiter_stop_without_start(self):
        """
        ConcurrencyLimitManager raises an exception if stop() is called without
        a prior call to start().
        """
        limiter = ConcurrencyLimitManager(1)
        self.assertRaises(Exception, limiter.stop)

    def test_concurrency_limiter_one_limit(self):
        """
        ConcurrencyLimitManager fires the next deferred in the queue when
        stop() is called.
        """
        limiter = ConcurrencyLimitManager(1)
        d1 = limiter.start("key")
        self.assertEqual(d1.called, True)
        d2 = limiter.start("key")
        self.assertEqual(d2.called, False)
        d3 = limiter.start("key")
        self.assertEqual(d3.called, False)

        # Stop the first concurrent and check that the second fires.
        limiter.stop("key")
        self.assertEqual(d2.called, True)
        self.assertEqual(d3.called, False)

        # Stop the second concurrent and check that the third fires.
        limiter.stop("key")
        self.assertEqual(d3.called, True)

        # Stop the third concurrent and check that we don't hang on to state.
        limiter.stop("key")
        self.assertEqual(limiter._concurrency_limiters, {})

    def test_concurrency_limiter_two_limit(self):
        """
        ConcurrencyLimitManager fires the next deferred in the queue when
        stop() is called.
        """
        limiter = ConcurrencyLimitManager(2)
        d1 = limiter.start("key")
        self.assertEqual(d1.called, True)
        d2 = limiter.start("key")
        self.assertEqual(d2.called, True)
        d3 = limiter.start("key")
        self.assertEqual(d3.called, False)
        d4 = limiter.start("key")
        self.assertEqual(d4.called, False)

        # Stop a concurrent and check that the third fires.
        limiter.stop("key")
        self.assertEqual(d3.called, True)
        self.assertEqual(d4.called, False)

        # Stop a concurrent and check that the fourth fires.
        limiter.stop("key")
        self.assertEqual(d4.called, True)

        # Stop the last concurrents and check that we don't hang on to state.
        limiter.stop("key")
        limiter.stop("key")
        self.assertEqual(limiter._concurrency_limiters, {})

    def test_concurrency_limiter_multiple_keys(self):
        """
        ConcurrencyLimitManager handles different keys independently.
        """
        limiter = ConcurrencyLimitManager(1)
        d1a = limiter.start("key-a")
        self.assertEqual(d1a.called, True)
        d2a = limiter.start("key-a")
        self.assertEqual(d2a.called, False)
        d1b = limiter.start("key-b")
        self.assertEqual(d1b.called, True)
        d2b = limiter.start("key-b")
        self.assertEqual(d2b.called, False)

        # Stop "key-a" and check that the next "key-a" fires.
        limiter.stop("key-a")
        self.assertEqual(d2a.called, True)
        self.assertEqual(d2b.called, False)

        # Stop "key-b" and check that the next "key-b" fires.
        limiter.stop("key-b")
        self.assertEqual(d2b.called, True)

        # Stop the last concurrents and check that we don't hang on to state.
        limiter.stop("key-a")
        limiter.stop("key-b")
        self.assertEqual(limiter._concurrency_limiters, {})

    def test_concurrency_limiter_negative_key(self):
        """
        ConcurrencyLimiter cannot have a negative concurrents
        """
        limiter = ConcurrencyLimitManager(1)
        limiter.start('key')
        limiter._concurrency_limiters['key']._concurrents = 0
        self.assertRaises(ConcurrencyLimiterError, limiter.stop, 'key')
