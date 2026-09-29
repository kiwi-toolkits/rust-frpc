//! Reconnect backoff, a faithful port of `pkg/util/wait/backoff.go`.
//!
//! A plain capped exponential is not what the Go client does. `fastBackoffImpl`
//! layers a burst of fast retries on top of the slow curve, so a server restart
//! recovers in a few hundred milliseconds instead of after a 20 s wait:
//!
//! * the very first call returns `duration` (1 s) outright;
//! * while the previous attempt failed, the first `fast_retry_count` calls that
//!   fall inside a `fast_retry_window` return `fast_retry_delay` jittered by
//!   `fast_retry_jitter`;
//! * everything else grows the previous delay by `factor`, jittered by `jitter`
//!   and capped at `max_duration`.
//!
//! Two details are easy to "fix" into incompatibility. `counts_in_fast_retry_window`
//! starts at 1, not 0; and the window only resets when a call overflows it, which
//! resets the counter to 0 mid-sequence. Both are reproduced as-is.

use std::time::{Duration, Instant};

/// `wait.FastBackoffOptions`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct FastBackoffOptions {
    /// Delay returned by the very first call.
    pub duration: Duration,
    /// Multiplier applied to the previous delay.
    pub factor: f64,
    /// Random spread added to the slow curve, as a fraction of the delay.
    pub jitter: f64,
    /// Ceiling for the slow curve. Zero means no ceiling.
    pub max_duration: Duration,
    /// Delay used once, on the first failure, when non-zero.
    pub init_duration_if_fail: Duration,
    /// How many fast retries are allowed per window. Zero disables them.
    pub fast_retry_count: u32,
    /// Spacing of the fast retries.
    pub fast_retry_delay: Duration,
    /// Random spread added to the fast retries, as a fraction of the delay.
    pub fast_retry_jitter: f64,
    /// How long a window of fast retries lasts.
    pub fast_retry_window: Duration,
}

impl Default for FastBackoffOptions {
    /// The values `client/service.go:294-305` passes to
    /// `wait.NewFastBackoffManager` for control-session reconnection.
    fn default() -> Self {
        Self {
            duration: Duration::from_secs(1),
            factor: 2.0,
            jitter: 0.1,
            max_duration: Duration::from_secs(20),
            init_duration_if_fail: Duration::ZERO,
            fast_retry_count: 3,
            fast_retry_delay: Duration::from_millis(200),
            fast_retry_jitter: 0.5,
            fast_retry_window: Duration::from_secs(60),
        }
    }
}

/// `wait.fastBackoffImpl`.
#[derive(Debug, Clone)]
pub struct FastBackoff {
    options: FastBackoffOptions,
    /// When `backoff` was last called. `None` means it never has been.
    last_called: Option<Duration>,
    consecutive_err_count: u32,
    fast_retry_cutoff: Option<Duration>,
    counts_in_fast_retry_window: u32,
}

impl FastBackoff {
    pub fn new(options: FastBackoffOptions) -> Self {
        Self {
            options,
            last_called: None,
            consecutive_err_count: 0,
            fast_retry_cutoff: None,
            // Note the initial 1, not 0 — see the module docs.
            counts_in_fast_retry_window: 1,
        }
    }

    /// The delay to wait before the next attempt.
    ///
    /// * `elapsed` is the caller's monotonic clock reading.
    /// * `previous_duration` is whatever this method returned last time, which is
    ///   what the slow curve grows from.
    /// * `previous_condition_error` is whether the last attempt failed; when it is
    ///   false the slow curve resets and `options.duration` comes back.
    pub fn backoff(
        &mut self,
        elapsed: Duration,
        previous_duration: Duration,
        previous_condition_error: bool,
    ) -> Duration {
        let Some(_) = self.last_called else {
            self.last_called = Some(elapsed);
            return self.options.duration;
        };
        self.last_called = Some(elapsed);

        if previous_condition_error {
            self.consecutive_err_count += 1;
        } else {
            self.consecutive_err_count = 0;
        }

        if self.options.fast_retry_count > 0 && previous_condition_error {
            self.counts_in_fast_retry_window += 1;
            if self.counts_in_fast_retry_window <= self.options.fast_retry_count {
                return jitter(
                    self.options.fast_retry_delay,
                    self.options.fast_retry_jitter,
                );
            }
            let cutoff = self.fast_retry_cutoff.unwrap_or(Duration::ZERO);
            if elapsed > cutoff {
                self.fast_retry_cutoff = Some(elapsed + self.options.fast_retry_window);
                self.counts_in_fast_retry_window = 0;
            }
        }

        if previous_condition_error {
            let mut duration = if self.consecutive_err_count == 1 {
                empty_or(self.options.init_duration_if_fail, previous_duration)
            } else {
                previous_duration
            };
            duration = empty_or(duration, Duration::from_secs(1));
            if self.options.factor != 0.0 {
                duration = duration.mul_f64(self.options.factor);
            }
            if self.options.jitter > 0.0 {
                duration = jitter(duration, self.options.jitter);
            }
            if !self.options.max_duration.is_zero() && duration > self.options.max_duration {
                duration = self.options.max_duration;
            }
            return duration;
        }

        self.options.duration
    }
}

/// A [`FastBackoff`] that reads the clock itself.
#[derive(Debug, Clone)]
pub struct Backoff {
    inner: FastBackoff,
    start: Instant,
    previous_duration: Duration,
    first: bool,
}

impl Backoff {
    pub fn new(options: FastBackoffOptions) -> Self {
        Self {
            inner: FastBackoff::new(options),
            start: Instant::now(),
            previous_duration: options.duration,
            first: true,
        }
    }

    /// The delay before the next attempt. Call once per attempt, *after* the
    /// attempt failed or succeeded.
    pub fn next(&mut self, previous_condition_error: bool) -> Duration {
        let elapsed = self.start.elapsed();
        let previous = if self.first {
            // The Go implementation passes the zero value on the first call; it
            // only matters once `consecutive_err_count` exceeds 1.
            self.first = false;
            Duration::ZERO
        } else {
            self.previous_duration
        };
        let delay = self
            .inner
            .backoff(elapsed, previous, previous_condition_error);
        self.previous_duration = delay;
        delay
    }

    /// Forgets the failure history, so the next outage starts from a fast retry.
    pub fn reset(&mut self) {
        *self = Self::new(self.inner.options);
    }
}

impl Default for Backoff {
    fn default() -> Self {
        Self::new(FastBackoffOptions::default())
    }
}

/// `util.EmptyOr`.
fn empty_or(value: Duration, fallback: Duration) -> Duration {
    if value.is_zero() {
        fallback
    } else {
        value
    }
}

/// `wait.Jitter`: `duration + rand * max_factor * duration`, so the result is
/// never *shorter* than the requested delay — it only ever stretches it.
///
/// Note that a `max_factor` of zero is treated as `1.0`, matching Go, so there is
/// no way to ask for "no jitter" by passing zero.
fn jitter(duration: Duration, max_factor: f64) -> Duration {
    let max_factor = if max_factor <= 0.0 { 1.0 } else { max_factor };
    let spread = rand::random::<f64>() * max_factor * duration.as_secs_f64();
    duration.saturating_add(Duration::from_secs_f64(spread))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The slow curve's `jitter` is 0.1, so a delay lands within 10% above its
    /// base. The fast retries use 0.5, i.e. up to 50% above 200 ms.
    const FAST: (Duration, Duration) = (Duration::from_millis(200), Duration::from_millis(300));

    #[test]
    fn the_first_call_returns_the_base_duration() {
        let mut backoff = FastBackoff::new(FastBackoffOptions::default());
        assert_eq!(
            backoff.backoff(Duration::ZERO, Duration::ZERO, true),
            Duration::from_secs(1)
        );
    }

    #[test]
    fn a_success_resets_to_the_base_duration() {
        let mut backoff = FastBackoff::new(FastBackoffOptions::default());
        backoff.backoff(Duration::ZERO, Duration::ZERO, true);
        assert_eq!(
            backoff.backoff(Duration::from_secs(2), Duration::from_secs(8), false),
            Duration::from_secs(1)
        );
    }

    /// Walks the sequence the Go state machine produces with
    /// `FastBackoffOptions::default()`. Three things are being pinned: the first
    /// call returns the base duration, the counter starting at 1 means only two
    /// fast retries follow it, and the mid-sequence window reset puts the counter
    /// back so fast retries resume.
    #[test]
    fn fast_retries_precede_the_slow_curve() {
        let mut backoff = FastBackoff::new(FastBackoffOptions::default());
        let mut previous = Duration::ZERO;
        let mut now = Duration::ZERO;
        let mut delays = Vec::new();
        for _ in 0..6 {
            previous = backoff.backoff(now, previous, true);
            delays.push(previous);
            now += Duration::from_millis(10);
        }

        assert_eq!(delays[0], Duration::from_secs(1));
        // Fast retries: jittered up to +50%.
        for index in [1, 2, 4, 5] {
            assert!(
                delays[index] >= FAST.0 && delays[index] <= FAST.1,
                "delay {index} = {:?} is not a fast retry",
                delays[index]
            );
        }
        // The third failure overflows the counter, resets the window, and falls
        // through to the slow curve: previous * 2, jittered up to +10%.
        assert!(
            delays[3] >= Duration::from_millis(400) && delays[3] <= Duration::from_millis(660),
            "delay 3 = {:?} is not on the slow curve",
            delays[3]
        );
        assert!(delays[3] > delays[2]);
    }

    #[test]
    fn the_slow_curve_is_capped() {
        let options = FastBackoffOptions {
            fast_retry_count: 0,
            max_duration: Duration::from_secs(20),
            ..FastBackoffOptions::default()
        };
        let mut backoff = FastBackoff::new(options);
        let mut previous = Duration::ZERO;
        let mut now = Duration::from_secs(1000);
        let mut last = Duration::ZERO;
        for _ in 0..40 {
            now += Duration::from_secs(600);
            previous = backoff.backoff(now, previous, true);
            last = previous;
        }
        assert_eq!(last, Duration::from_secs(20));
    }

    #[test]
    fn init_duration_if_fail_overrides_the_previous_delay_once() {
        let options = FastBackoffOptions {
            init_duration_if_fail: Duration::from_millis(500),
            fast_retry_count: 0,
            jitter: 0.0,
            ..FastBackoffOptions::default()
        };
        // A zero `jitter` means "Go's default of 1.0", so normalize it by hand.
        let options = FastBackoffOptions {
            jitter: 0.0000001,
            ..options
        };
        let mut backoff = FastBackoff::new(options);
        let first = backoff.backoff(Duration::ZERO, Duration::ZERO, true);
        assert_eq!(first, Duration::from_secs(1));
        // consecutive_err_count == 1 on this call, so the override applies.
        let second = backoff.backoff(Duration::from_secs(1), first, true);
        assert!(second >= Duration::from_secs(1) && second < Duration::from_millis(1001));
    }

    #[test]
    fn jitter_never_shrinks_a_delay() {
        let duration = Duration::from_secs(1);
        for _ in 0..50 {
            let jittered = jitter(duration, 0.5);
            assert!(jittered >= duration);
            assert!(jittered <= duration + Duration::from_millis(500));
        }
    }

    #[test]
    fn reset_restores_the_initial_state() {
        let mut backoff = Backoff::new(FastBackoffOptions::default());
        for _ in 0..10 {
            backoff.next(true);
        }
        backoff.reset();
        assert_eq!(backoff.next(true), Duration::from_secs(1));
    }
}
