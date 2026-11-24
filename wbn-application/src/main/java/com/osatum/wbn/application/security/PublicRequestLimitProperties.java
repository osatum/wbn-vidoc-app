package com.osatum.wbn.application.security;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Positive;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;
import org.springframework.validation.annotation.Validated;

@Getter
@Component
@Validated
@ConfigurationProperties(prefix = "app.public-request-limits")
public class PublicRequestLimitProperties {
    @Valid
    private final Login login = new Login();
    @Valid
    private final Registration registration = new Registration();

    @Getter
    @Setter
    public static class Login {
        @Positive private int maxFailures = 5;
        @Positive private int windowMinutes = 15;
        @Positive private int initialDelaySeconds = 30;
        @Positive private int maxDelaySeconds = 300;
        @Positive private int ipObservationThreshold = 100;
        @Positive private int ipObservationWindowMinutes = 5;
    }

    @Getter
    @Setter
    public static class Registration {
        @Positive private int maxSubmissions = 3;
        @Positive private int windowMinutes = 30;
        @Positive private int ipObservationThreshold = 60;
        @Positive private int ipObservationWindowMinutes = 15;
    }
}
