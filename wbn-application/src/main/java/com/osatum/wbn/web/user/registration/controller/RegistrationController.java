package com.osatum.wbn.web.user.registration.controller;

import com.osatum.wbn.application.security.PublicRequestRateLimiter;
import com.osatum.wbn.application.user.dto.RegistrationActivationResultDto;
import com.osatum.wbn.application.user.dto.RegistrationAvailabilityDto;
import com.osatum.wbn.application.user.dto.RegistrationInstitutionDto;
import com.osatum.wbn.application.user.dto.RegistrationSubmitResultDto;
import com.osatum.wbn.application.user.service.AccountActivationService;
import com.osatum.wbn.application.user.service.RegistrationInstitutionService;
import com.osatum.wbn.application.user.service.RegistrationSubmitService;
import com.osatum.wbn.web.error.ApiErrorResponse;
import com.osatum.wbn.web.shared.request.ClientRequestMetadataResolver;
import com.osatum.wbn.web.user.registration.form.RegistrationSubmitForm;
import com.osatum.wbn.web.user.registration.mapper.RegistrationSubmitFormMapper;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@Tag(name = "registration", description = "Rejestracja użytkowników do jednostek naukowych")
@RestController
@RequestMapping("/api/registration")
@RequiredArgsConstructor
public class RegistrationController {
    private final RegistrationInstitutionService registrationInstitutionService;
    private final RegistrationSubmitService registrationSubmitService;
    private final RegistrationSubmitFormMapper registrationSubmitFormMapper;
    private final AccountActivationService accountActivationService;
    private final ClientRequestMetadataResolver requestMetadataResolver;
    private final PublicRequestRateLimiter requestRateLimiter;

    @GetMapping("/institutions")
    @Operation(
            summary = "Lista instytucji dostępnych do rejestracji ogólnej",
            description = "Zwraca aktywne jednostki naukowe z włączoną rejestracją, uwzględniając ustawienie dopuszczenia innych adresów IP oraz reguły IP instytucji dla adresu klienta."
    )
    @ApiResponse(responseCode = "200", description = "Zwrócono listę instytucji dostępnych do rejestracji")
    public List<RegistrationInstitutionDto> findGeneralRegistrationInstitutions(HttpServletRequest request) {
        return registrationInstitutionService.findGeneralRegistrationInstitutions(requestMetadataResolver.resolve(request).ipAddress());
    }

    @GetMapping("/institutions/by-ip")
    @Operation(
            summary = "Lista instytucji dostępnych po adresie IP",
            description = "Zwraca aktywne jednostki naukowe z włączoną rejestracją, dla których adres IP klienta pasuje do aktywnych reguł IP instytucji."
    )
    @ApiResponse(responseCode = "200", description = "Zwrócono listę instytucji dopasowanych do adresu IP")
    public List<RegistrationInstitutionDto> findIpRegistrationInstitutions(HttpServletRequest request) {
        return registrationInstitutionService.findIpRegistrationInstitutions(requestMetadataResolver.resolve(request).ipAddress());
    }

    @GetMapping("/institutions/{id}/availability")
    @Operation(
            summary = "Sprawdzenie dostępności rejestracji w instytucji",
            description = "Sprawdza, czy wybrana instytucja jest aktywna, ma włączoną rejestrację, jest jednostką naukową i dopuszcza rejestrację z adresu IP klienta."
    )
    @ApiResponse(responseCode = "200", description = "Zwrócono wynik sprawdzenia dostępności rejestracji",
            content = @Content(mediaType = "application/json", schema = @Schema(implementation = RegistrationAvailabilityDto.class)))
    public RegistrationAvailabilityDto validateRegistrationStart(
            @PathVariable(name = "id") Long id,
            HttpServletRequest request
    ) {
        return registrationInstitutionService.validateRegistrationStart(id, requestMetadataResolver.resolve(request).ipAddress());
    }

    @PostMapping("/institutions/{id}/submit")
    @Operation(
            summary = "Wysłanie formularza rejestracyjnego",
            description = "Przyjmuje formularz dla wybranej instytucji. Wynik jest taki sam dla nowego i istniejącego konta."
    )
    @ApiResponse(responseCode = "202", description = "Przyjęto zgłoszenie do obsługi",
            content = @Content(mediaType = "application/json", schema = @Schema(implementation = RegistrationSubmitResultDto.class)))
    @ApiResponse(responseCode = "400", description = "Błąd walidacji formularza",
            content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiErrorResponse.class)))
    @ApiResponse(responseCode = "404", description = "Nie znaleziono instytucji",
            content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiErrorResponse.class)))
    @ApiResponse(responseCode = "429", description = "Limit zgłoszeń. Retry-After podaje czas oczekiwania w sekundach.",
            content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiErrorResponse.class)))
    public ResponseEntity<RegistrationSubmitResultDto> submitRegistration(
            @PathVariable(name = "id") Long id,
            @Valid @RequestBody RegistrationSubmitForm form,
            HttpServletRequest request
    ) {
        var requestMetadata = requestMetadataResolver.resolve(request);
        // Obserwacja IP ma własną transakcję, więc zapis pozostaje także po odrzuceniu zgłoszenia przez serwis.
        requestRateLimiter.observeRegistrationIp(requestMetadata.ipAddress());
        RegistrationSubmitResultDto result = registrationSubmitService.submit(
                registrationSubmitFormMapper.toDto(id, form),
                requestMetadata.ipAddress(),
                requestMetadata.userAgent()
        );
        return ResponseEntity.accepted().body(result);
    }

    @PostMapping("/activation/{token}")
    @Operation(
            summary = "Aktywacja rejestracji tokenem",
            description = "Aktywuje zgłoszenie rejestracyjne na podstawie tokenu z wiadomości e-mail i zapisuje metadane kliknięcia linku aktywacyjnego."
    )
    @ApiResponse(responseCode = "200", description = "Rejestracja została aktywowana lub zwrócono jej status",
            content = @Content(mediaType = "application/json", schema = @Schema(implementation = RegistrationActivationResultDto.class)))
    @ApiResponse(responseCode = "400", description = "Nieprawidłowy token aktywacyjny",
            content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiErrorResponse.class)))
    public RegistrationActivationResultDto activateRegistration(
            @PathVariable(name = "token") String token,
            HttpServletRequest request
    ) {
        var requestMetadata = requestMetadataResolver.resolve(request);
        return accountActivationService.activate(
                token,
                requestMetadata.ipAddress(),
                requestMetadata.userAgent()
        );
    }
}
