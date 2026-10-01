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

    // Charge socket setup to the original deadline. The timer uses OS waits
    // without rounding each short timeout up to Tokio's next millisecond tick.
    let delay = futures_timer::Delay::new(duration.saturating_sub(started.elapsed()));
    match select(operation, delay).await {
        Either::Left((result, _)) => result,
        Either::Right(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "future timed out")),
    }
}
