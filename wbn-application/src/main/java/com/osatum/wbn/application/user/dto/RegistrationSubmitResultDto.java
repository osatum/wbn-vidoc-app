package com.osatum.wbn.application.user.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.osatum.wbn.domain.model.institution.InstitutionRole;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class RegistrationSubmitResultDto {
    private Long userId;
    private Long institutionId;
    private Long membershipId;
    private InstitutionRole role;
    private RegistrationSubmitStatus status;
}
