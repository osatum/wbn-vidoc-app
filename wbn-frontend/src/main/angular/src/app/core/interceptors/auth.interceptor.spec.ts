import { HttpErrorResponse, HttpHandlerFn, HttpRequest, HttpResponse } from '@angular/common/http';
import { TestBed } from '@angular/core/testing';
import { of, Subject, throwError } from 'rxjs';

import { BASE_PATH } from '../backend/variables';
import { AuthService } from '../services/auth.service';
import { withLocalUnauthorizedHandling } from './auth-error-context';
import { authInterceptor } from './auth.interceptor';

describe('authInterceptor', () => {
  const backend = 'https://wbn-api.example.test:8443/gateway';
  let authService: {
    token: ReturnType<typeof vi.fn>;
    refreshOnce: ReturnType<typeof vi.fn>;
    handleIpAccessDenied: ReturnType<typeof vi.fn>;
  };

  beforeEach(() => {
    authService = {
      token: vi.fn(() => 'access-token'),
      refreshOnce: vi.fn(),
      handleIpAccessDenied: vi.fn(),
    };

    TestBed.configureTestingModule({
      providers: [
        { provide: BASE_PATH, useValue: backend },
        { provide: AuthService, useValue: authService },
      ],
    });
  });

  it('does not refresh token for locally handled unauthorized errors', () => {
    const request = new HttpRequest('PUT', '/api/profile/password', {}, {
      context: withLocalUnauthorizedHandling(),
    });
    const next: HttpHandlerFn = vi.fn(() => throwError(() => new HttpErrorResponse({
      status: 401,
      error: {
        code: 'AUTHENTICATION_FAILED',
      },
    })));
    let emittedError: unknown;

    TestBed.runInInjectionContext(() => {
      authInterceptor(request, next).subscribe({
        error: (error) => {
          emittedError = error;
        },
      });
    });

    expect(emittedError).toBeInstanceOf(HttpErrorResponse);
    expect(authService.refreshOnce).not.toHaveBeenCalled();
    expect(next).toHaveBeenCalledTimes(1);
  });

  it.each([
    '/api/auth/select-institution',
    `${backend}/api/auth/select-institution`,
  ])('attaches the access token when selecting another context at %s', (url) => {
    const request = new HttpRequest('POST', url, {
      institutionId: 20,
      membershipId: 30,
    });
    const next: HttpHandlerFn = vi.fn(() => of(new HttpResponse({ status: 200 })));

    TestBed.runInInjectionContext(() => {
      authInterceptor(request, next).subscribe();
    });

    const forwardedRequest = vi.mocked(next).mock.calls[0][0];
    expect(forwardedRequest.headers.get('Authorization')).toBe('Bearer access-token');
  });

  it.each([
    '/api/profile',
    `${backend}/api/profile?filter=/api/auth/login`,
  ])('sends the access token to trusted API %s', (url) => {
    const request = new HttpRequest('GET', url);
    const next = vi.fn<HttpHandlerFn>(() => of(new HttpResponse({ status: 200 })));

    TestBed.runInInjectionContext(() => authInterceptor(request, next).subscribe());

    expect(next.mock.calls[0][0].headers.get('Authorization')).toBe('Bearer access-token');
  });

  it.each([
    '/assets/i18n/pl.json?path=/api/profile',
    '/api/../assets/i18n/pl.json',
    'https://outside.example.test/api/profile',
    '//outside.example.test/api/auth/select-institution',
    'https://wbn-api.example.test/gateway/api/profile',
    'http://wbn-api.example.test:8443/gateway/api/profile',
    'https://wbn-api.example.test:8443/another/api/profile',
    'https://wbn-api.example.test.outside.example.test:8443/gateway/api/profile',
  ])('passes %s through without adding Authorization or refreshing the session', (url) => {
    const request = new HttpRequest('GET', url);
    const denied = new HttpErrorResponse({ status: 401 });
    const next = vi.fn<HttpHandlerFn>(() => throwError(() => denied));
    const error = vi.fn();

    TestBed.runInInjectionContext(() => authInterceptor(request, next).subscribe({ error }));

    expect(next).toHaveBeenCalledExactlyOnceWith(request);
    expect(next.mock.calls[0][0].headers.has('Authorization')).toBe(false);
    expect(authService.refreshOnce).not.toHaveBeenCalled();
    expect(error).toHaveBeenCalledWith(denied);
  });

  it.each([
    '/api/institution/7',
    '/api/auth/refresh',
    '/api/auth/select-institution',
  ])('handles IP denial from %s without refreshing', (url) => {
    const request = new HttpRequest('POST', url, {});
    const next: HttpHandlerFn = vi.fn(() => throwError(() => new HttpErrorResponse({
      status: 403,
      error: { code: 'IP_ACCESS_DENIED' },
    })));
    let emittedError: unknown;

    TestBed.runInInjectionContext(() => {
      authInterceptor(request, next).subscribe({
        error: (error) => {
          emittedError = error;
        },
      });
    });

    expect(emittedError).toBeInstanceOf(HttpErrorResponse);
    expect(authService.handleIpAccessDenied).toHaveBeenCalledOnce();
    expect(authService.refreshOnce).not.toHaveBeenCalled();
  });

  it('retries only once when the refreshed request is still unauthorized', () => {
    const request = new HttpRequest('GET', '/api/profile');
    const denied = new HttpErrorResponse({ status: 401 });
    const next = vi.fn<HttpHandlerFn>(() => throwError(() => denied));
    const error = vi.fn();
    authService.refreshOnce.mockImplementation(() => {
      authService.token.mockReturnValue('refreshed-token');
      return of({});
    });

    TestBed.runInInjectionContext(() => authInterceptor(request, next).subscribe({ error }));

    expect(authService.refreshOnce).toHaveBeenCalledOnce();
    expect(next).toHaveBeenCalledTimes(2);
    expect(next.mock.calls[1][0].headers.get('Authorization')).toBe('Bearer refreshed-token');
    expect(error).toHaveBeenCalledWith(denied);
  });

  it('reuses the updated token when an older request returns a late 401', () => {
    const originalA = new Subject<HttpResponse<unknown>>();
    const originalB = new Subject<HttpResponse<unknown>>();
    const next = vi.fn<HttpHandlerFn>(() => of(new HttpResponse({ status: 200 })))
      .mockReturnValueOnce(originalA)
      .mockReturnValueOnce(originalB);
    authService.refreshOnce.mockImplementation(() => {
      authService.token.mockReturnValue('refreshed-token');
      return of({});
    });
    TestBed.runInInjectionContext(() => {
      authInterceptor(new HttpRequest('GET', '/api/profile'), next).subscribe();
      authInterceptor(new HttpRequest('GET', '/api/institutions'), next).subscribe();
    });

    originalA.error(new HttpErrorResponse({ status: 401 }));
    originalB.error(new HttpErrorResponse({ status: 401 }));

    expect(authService.refreshOnce).toHaveBeenCalledOnce();
    expect(next).toHaveBeenCalledTimes(4);
    expect(next.mock.calls.slice(2).map(([request]) => request.headers.get('Authorization')))
      .toEqual(['Bearer refreshed-token', 'Bearer refreshed-token']);
  });

  it('leaves the first context selection to PRE_AUTH handling', () => {
    authService.token.mockReturnValue(null);
    const request = new HttpRequest('POST', '/api/auth/select-institution', {});
    const denied = new HttpErrorResponse({ status: 401 });
    const next = vi.fn<HttpHandlerFn>(() => throwError(() => denied));
    const error = vi.fn();

    TestBed.runInInjectionContext(() => authInterceptor(request, next).subscribe({ error }));

    expect(next).toHaveBeenCalledExactlyOnceWith(request);
    expect(authService.refreshOnce).not.toHaveBeenCalled();
    expect(error).toHaveBeenCalledWith(denied);
  });
});
