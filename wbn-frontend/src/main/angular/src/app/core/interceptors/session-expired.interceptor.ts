import { inject } from '@angular/core';
import { HttpErrorResponse, HttpInterceptorFn } from '@angular/common/http';
import { Router } from '@angular/router';
import { catchError, throwError } from 'rxjs';
import { AuthService } from '../services/auth.service';
import { getTrustedApiPath, isContextSelectionRequest, isPublicApiRequest } from './api-paths';
import { isLocallyHandledUnauthorized, SKIP_SESSION_REFRESH } from './auth-error-context';

export const sessionExpiredInterceptor: HttpInterceptorFn = (req, next) => {
  const apiPath = getTrustedApiPath(req.url);
  if (apiPath === null) {
    return next(req);
  }

  const auth = inject(AuthService);
  const router = inject(Router);
  const usesSession = !isPublicApiRequest(apiPath) || (isContextSelectionRequest(apiPath) && !!auth.token());

  return next(req).pipe(
    catchError((error: HttpErrorResponse) => {
      // Ten interceptor otrzymuje wynik po obsłudze odświeżenia. Tylko nieobsłużone 401 kończy lokalną sesję.
      if (usesSession && error.status === 401 && !req.context.get(SKIP_SESSION_REFRESH) &&
          !isLocallyHandledUnauthorized(req, error)) {
        auth.clearSession();
        void router.navigate(['/']);
      }

      return throwError(() => error);
    }),
  );
};
