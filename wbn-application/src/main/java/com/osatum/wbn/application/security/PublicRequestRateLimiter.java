package com.osatum.wbn.application.security;

import com.osatum.wbn.application.shared.exception.RequestRateLimitExceededException;
import com.osatum.wbn.domain.repository.auth.PublicRequestLimitRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Locale;
import java.util.function.Supplier;

/**
 * Limity obowiązują dla adresu e-mail niezależnie od instytucji i wielkości liter.
 * Obserwacja IP służy do sygnalizowania wzmożonego ruchu, bez blokowania osób korzystających ze wspólnej sieci.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class PublicRequestRateLimiter {
    private final PublicRequestLimitRepository repository;
    private final PublicRequestLimitProperties properties;
    private final Clock clock;

    @Transactional(propagation = Propagation.MANDATORY, noRollbackFor = BadCredentialsException.class)
    public <T> T authenticate(String email, String clientIp, Supplier<T> verifyCredentials) {
        var login = properties.getLogin();
        Duration window = Duration.ofMinutes(login.getWindowMinutes());
        String key = bucketKey("login-email", normalizeEmail(email));
        // Blokada licznika obejmuje także sprawdzenie hasła, żeby równoległe próby nie ominęły limitu.
        var blockedUntil = repository.lock(key, clock.instant().plus(window));
        Instant now = clock.instant();
        if (blockedUntil.filter(until -> until.isAfter(now)).isPresent()) {
            throw new RequestRateLimitExceededException(Duration.between(now, blockedUntil.orElseThrow()));
        }

        T verified;
        try {
            verified = verifyCredentials.get();
        } catch (BadCredentialsException failure) {
            recordLoginFailure(key, window, login);
            observeIp("login-ip", clientIp, login.getIpObservationThreshold(),
                    Duration.ofMinutes(login.getIpObservationWindowMinutes()));
            throw failure;
        }
        repository.clear(key);
        return verified;
    }

    @Transactional(propagation = Propagation.MANDATORY)
    public void consumeRegistrationAttempt(String email) {
        var registration = properties.getRegistration();
        Duration window = Duration.ofMinutes(registration.getWindowMinutes());
        String key = bucketKey("registration-email", normalizeEmail(email));
        repository.lock(key, clock.instant().plus(window));
        Instant now = clock.instant();
        Instant windowStart = now.minus(window);
        var attempts = repository.attemptsAfter(key, windowStart);
        if (attempts.size() >= registration.getMaxSubmissions()) {
            // Po obniżeniu limitu czekamy, aż z okna wypadnie tyle prób, by kolejna zmieściła się w nowym limicie.
            Instant retryAt = attempts.get(attempts.size() - registration.getMaxSubmissions()).plus(window);
            throw new RequestRateLimitExceededException(Duration.between(now, retryAt));
        }
        repository.recordAttempt(key, now, windowStart, now.plus(window), null);
    }

    @Transactional
    public void observeRegistrationIp(String clientIp) {
        var registration = properties.getRegistration();
        observeIp("registration-ip", clientIp, registration.getIpObservationThreshold(),
                Duration.ofMinutes(registration.getIpObservationWindowMinutes()));
    }

    private void recordLoginFailure(String key, Duration window, PublicRequestLimitProperties.Login login) {
        Instant now = clock.instant();
        Instant windowStart = now.minus(window);
        int failures = repository.attemptsAfter(key, windowStart).size() + 1;
        Instant blockedUntil = null;
        Instant expiresAt = now.plus(window);
        if (failures >= login.getMaxFailures()) {
            long delay = Math.min(login.getInitialDelaySeconds(), login.getMaxDelaySeconds());
            for (int count = login.getMaxFailures(); count < failures && delay < login.getMaxDelaySeconds(); count++) {
                delay = Math.min(delay * 2, login.getMaxDelaySeconds());
            }
            blockedUntil = now.plusSeconds(delay);
            // Licznik pozostaje w bazie do końca blokady, nawet jeśli okno zliczania skończy się wcześniej.
            if (blockedUntil.isAfter(expiresAt)) {
                expiresAt = blockedUntil;
            }
        }
        repository.recordAttempt(key, now, windowStart, expiresAt, blockedUntil);
    }

    private void observeIp(String scope, String clientIp, int threshold, Duration window) {
        if (clientIp == null || clientIp.isBlank()) {
            return;
        }

        String key = bucketKey(scope, clientIp);
        repository.lock(key, clock.instant().plus(window));
        Instant now = clock.instant();
        Instant windowStart = now.minus(window);
        int count = repository.attemptsAfter(key, windowStart).size();
        if (count < threshold) {
            repository.recordAttempt(key, now, windowStart, now.plus(window), null);
            if (count + 1 == threshold) {
                log.warn("Public request observation threshold reached for {} ({} attempts in {} minutes)",
                        scope, threshold, window.toMinutes());
            }
        }
    }

    @Scheduled(fixedDelayString = "PT15M")
    @Transactional
    public void removeExpiredBuckets() {
        repository.deleteExpired(clock.instant(), 5000);
    }

    private static String normalizeEmail(String email) {
        return email.trim().toLowerCase(Locale.ROOT);
    }

    private static String bucketKey(String scope, String identifier) {
        // W liczniku przechowujemy skrót zamiast jawnego adresu e-mail lub IP.
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest((scope + ":" + identifier).getBytes(StandardCharsets.UTF_8));
            return scope + ":" + HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is unavailable", exception);
        }
    }
}
