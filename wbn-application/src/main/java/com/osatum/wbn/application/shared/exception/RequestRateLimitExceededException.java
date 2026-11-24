package com.osatum.wbn.application.shared.exception;

import java.time.Duration;

public class RequestRateLimitExceededException extends RuntimeException {
    private final long retryAfterSeconds;

    public RequestRateLimitExceededException(Duration remaining) {
        super("Too many requests. Try again later.");
        this.retryAfterSeconds = Math.max(1, remaining.toSeconds() + (remaining.getNano() == 0 ? 0 : 1));
    }

    public long retryAfterSeconds() {
        return retryAfterSeconds;
    }
}
