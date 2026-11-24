import { HttpErrorResponse, HttpHandlerFn, HttpRequest } from '@angular/common/http';
import { TestBed } from '@angular/core/testing';
import { Router } from '@angular/router';
import { throwError } from 'rxjs';

import { AuthService } from '../services/auth.service';
import { withLocalUnauthorizedHandling } from './auth-error-context';
import { sessionExpiredInterceptor } from './session-expired.interceptor';

describe('sessionExpiredInterceptor', () => {
  let authService: {
    clearSession: ReturnType<typeof vi.fn>;
    token: ReturnType<typeof vi.fn>;
    refreshOnce: ReturnType<typeof vi.fn>;
  };
  let router: {
    navigate: ReturnType<typeof vi.fn>;
  };

  beforeEach(() => {
    authService = {
      clearSession: vi.fn(),
      token: vi.fn(() => 'access-token'),
      refreshOnce: vi.fn(),
    };
    router = {
      navigate: vi.fn(() => Promise.resolve(true)),
    };

    TestBed.configureTestingModule({
      providers: [
        { provide: AuthService, useValue: authService },
        { provide: Router, useValue: router },
      ],
    });
  });

  it('preserves the session for locally handled unauthorized errors', () => {
    const request = new HttpRequest('PUT', '/api/profile/password', {}, {
      context: withLocalUnauthorizedHandling(),
    });
    const next: HttpHandlerFn = () => throwError(() => new HttpErrorResponse({
      status: 401,
      error: {
        code: 'AUTHENTICATION_FAILED',
      },
    }));
    let emittedError: unknown;

    TestBed.runInInjectionContext(() => {
      sessionExpiredInterceptor(request, next).subscribe({
        error: (error) => {
          emittedError = error;
        },
      });
    });

    expect(emittedError).toBeInstanceOf(HttpErrorResponse);
    expect(authService.clearSession).not.toHaveBeenCalled();
    expect(router.navigate).not.toHaveBeenCalled();
  });

  it('clears the session for regular unauthorized errors', () => {
    const request = new HttpRequest('GET', '/api/profile');
    const next: HttpHandlerFn = () => throwError(() => new HttpErrorResponse({ status: 401 }));

    TestBed.runInInjectionContext(() => {
      sessionExpiredInterceptor(request, next).subscribe({
        error: () => undefined,
      });
    });

    expect(authService.clearSession).toHaveBeenCalledTimes(1);
    expect(router.navigate).toHaveBeenCalledWith(['/']);
  });

  it('passes through a permission denial without retrying or clearing the session', () => {
    const request = new HttpRequest('POST', '/api/restricted-operation', {});
    const denied = new HttpErrorResponse({ status: 403 });
    const next = vi.fn<HttpHandlerFn>(() => throwError(() => denied));
    const error = vi.fn();

    TestBed.runInInjectionContext(() => sessionExpiredInterceptor(request, next).subscribe({ error }));

    expect(error).toHaveBeenCalledWith(denied);
    expect(next).toHaveBeenCalledExactlyOnceWith(request);
    expect(authService.refreshOnce).not.toHaveBeenCalled();
    expect(authService.clearSession).not.toHaveBeenCalled();
    expect(router.navigate).not.toHaveBeenCalled();
  });

  it('preserves the local session after an unauthorized response from another origin', () => {
    const request = new HttpRequest('GET', 'https://outside.example.test/api/profile');
    const denied = new HttpErrorResponse({ status: 401 });
    const next = vi.fn<HttpHandlerFn>(() => throwError(() => denied));
    const error = vi.fn();

    TestBed.runInInjectionContext(() => sessionExpiredInterceptor(request, next).subscribe({ error }));

    expect(error).toHaveBeenCalledWith(denied);
    expect(authService.clearSession).not.toHaveBeenCalled();
    expect(router.navigate).not.toHaveBeenCalled();
  });
});
