package com.osatum.wbn.application.auth.service;

import org.springframework.security.access.AccessDeniedException;

public class IpAccessDeniedException extends AccessDeniedException {
    public IpAccessDeniedException() {
        super("Access is not allowed from this IP address");
    }
}
