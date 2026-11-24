package com.osatum.wbn.domain.repository.auth;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

public interface PublicRequestLimitRepository {
    Optional<Instant> lock(String bucketKey, Instant expiresAt);

    List<Instant> attemptsAfter(String bucketKey, Instant windowStart);

    void recordAttempt(String bucketKey, Instant now, Instant windowStart, Instant expiresAt, Instant blockedUntil);

    void clear(String bucketKey);

    void deleteExpired(Instant now, int limit);
}
