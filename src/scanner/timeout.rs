use futures::future::{select, Either};
use std::{
    future::Future,
    io,
    task::Poll,
    time::{Duration, Instant},
};

/// Preserve I/O errors and cancel pending operations when their deadline expires.
/// Poll once before allocating a timer so immediate replies pay no timer cost.
pub(super) async fn io_timeout<T>(
    duration: Duration,
    operation: impl Future<Output = io::Result<T>>,
) -> io::Result<T> {
    let started = Instant::now();
    futures::pin_mut!(operation);
    if let Poll::Ready(result) = futures::poll!(operation.as_mut()) {
        return result;
    }

    let Some(deadline) = started.checked_add(duration) else {
        return operation.await;
    };

    // Most replies arrive well before a normal scan timeout. Keep their timers
    // on Tokio's reactor to avoid registering each socket's deadline with a
    // second reactor. Leave 32 ms for the precise timer to allow for coarse
    // timer rounding (including Windows). Short timeouts use the
    // precise timer immediately; neither phase changes the original deadline.
    // Allocate this state only for pending I/O. Keeping it out of the outer
    // future also keeps FuturesUnordered entries small for immediate results.
    let delay = Box::pin(async move {
        const PRECISE_WINDOW: Duration = Duration::from_millis(32);
        if deadline.saturating_duration_since(Instant::now()) > PRECISE_WINDOW {
            tokio::time::sleep_until(tokio::time::Instant::from_std(deadline - PRECISE_WINDOW))
                .await;
        }

        // OS waits avoid rounding every short timeout to the next millisecond.
        async_io::Timer::at(deadline).await;
    });
    match select(operation, delay).await {
        Either::Left((result, _)) => result,
        Either::Right(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "future timed out")),
    }
}
