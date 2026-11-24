package com.osatum.wbn.infrastructure.persistence;

import com.osatum.wbn.domain.repository.auth.PublicRequestLimitRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;

@Repository
@RequiredArgsConstructor
public class PublicRequestLimitRepositoryAdapter implements PublicRequestLimitRepository {
    private final JdbcTemplate jdbc;

    @Override
    public Optional<Instant> lock(String bucketKey, Instant expiresAt) {
        // Czyszczenie może usunąć wygasły licznik między próbą wstawienia rekordu a odczytem z blokadą.
        for (int attempt = 0; attempt < 2; attempt++) {
            jdbc.update("""
                    insert into public_request_limit (bucket_key, expires_at)
                    values (?, ?) on conflict do nothing
                    """, bucketKey, timestamp(expiresAt));
            List<Optional<Instant>> buckets = jdbc.query("""
                    select blocked_until from public_request_limit where bucket_key = ? for update
                    """, (rs, rowNum) -> Optional.ofNullable(rs.getObject(1, OffsetDateTime.class))
                    .map(OffsetDateTime::toInstant), bucketKey);
            if (!buckets.isEmpty()) {
                return buckets.getFirst();
            }
        }
        throw new IllegalStateException("Could not lock public request limit");
    }

    @Override
    public List<Instant> attemptsAfter(String bucketKey, Instant windowStart) {
        return jdbc.query("""
                select occurred_at from public_request_attempt
                where bucket_key = ? and occurred_at > ?
                order by occurred_at
                """, (rs, rowNum) -> rs.getObject(1, OffsetDateTime.class).toInstant(),
                bucketKey, timestamp(windowStart));
    }

    @Override
    public void recordAttempt(String bucketKey, Instant now, Instant windowStart, Instant expiresAt, Instant blockedUntil) {
        jdbc.update("delete from public_request_attempt where bucket_key = ? and occurred_at <= ?",
                bucketKey, timestamp(windowStart));
        jdbc.update("insert into public_request_attempt (bucket_key, occurred_at) values (?, ?)",
                bucketKey, timestamp(now));
        jdbc.update("update public_request_limit set expires_at = ?, blocked_until = ? where bucket_key = ?",
                timestamp(expiresAt), blockedUntil == null ? null : timestamp(blockedUntil), bucketKey);
    }

    @Override
    public void clear(String bucketKey) {
        jdbc.update("delete from public_request_limit where bucket_key = ?", bucketKey);
    }

    @Override
    public void deleteExpired(Instant now, int limit) {
        // Czyszczenie pomija liczniki zablokowane przez inne transakcje, żeby nie czekać na obsługę żądań.
        jdbc.update("""
                delete from public_request_limit where bucket_key in (
                    select bucket_key from public_request_limit
                    where expires_at <= ?
                    order by expires_at limit ? for update skip locked
                )
                """, timestamp(now), limit);
    }

    private static OffsetDateTime timestamp(Instant instant) {
        return instant.atOffset(ZoneOffset.UTC);
    }
}
