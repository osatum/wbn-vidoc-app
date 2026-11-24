package com.osatum.wbn.infrastructure.persistence.springdata;

import com.osatum.wbn.domain.model.auth.LoginSession;
import com.osatum.wbn.domain.model.auth.LoginSessionStatus;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

@Repository
public interface LoginSessionSpringDataRepository extends JpaRepository<LoginSession, Long>, JpaSpecificationExecutor<LoginSession> {
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select session from LoginSession session where session.id = :id")
    Optional<LoginSession> findByIdForUpdate(@Param("id") Long id);

    List<LoginSession> findByStatusAndExpiresAtLessThanEqual(LoginSessionStatus status, Instant now);

    List<LoginSession> findByUserIdAndStatusAndExpiresAtAfterAndEndedAtIsNull(Long userId, LoginSessionStatus status, Instant now);

    List<LoginSession> findByInstitutionIdAndStatusAndExpiresAtAfterAndEndedAtIsNull(Long institutionId, LoginSessionStatus status, Instant now);
}
