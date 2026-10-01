use std::{
    future::{poll_fn, Future},
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
    let mut delay = None;

    // Most replies arrive well before a normal scan timeout. Keep their timers
    // on Tokio's reactor to avoid registering each socket's deadline with a
    // second reactor. Leave 32 ms for the precise timer to allow for coarse
    // timer rounding (including Windows). Short timeouts use the
    // precise timer immediately; neither phase changes the original deadline.
    // Allocate this state only for pending I/O. Keeping it out of the outer
    // future also keeps FuturesUnordered entries small for immediate results.
    poll_fn(|context| {
        if let Poll::Ready(result) = operation.as_mut().poll(context) {
            return Poll::Ready(result);
        }

        let delay = delay.get_or_insert_with(|| {
            Box::pin(async move {
                let Some(deadline) = started.checked_add(duration) else {
                    return std::future::pending::<()>().await;
                };
                const PRECISE_WINDOW: Duration = Duration::from_millis(32);
                if deadline.saturating_duration_since(Instant::now()) > PRECISE_WINDOW {
                    tokio::time::sleep_until(tokio::time::Instant::from_std(
                        deadline - PRECISE_WINDOW,
                    ))
                    .await;
                }

                // OS waits avoid rounding every short timeout to the next millisecond.
                async_io::Timer::at(deadline).await;
            })
        });
        if delay.as_mut().poll(context).is_ready() {
            Poll::Ready(Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "future timed out",
            )))
        } else {
            Poll::Pending
        }
    })
    .await
}
