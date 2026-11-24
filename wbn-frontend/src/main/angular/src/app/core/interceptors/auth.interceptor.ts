import {inject} from '@angular/core';
import {HttpErrorResponse, HttpHandlerFn, HttpInterceptorFn} from '@angular/common/http';
import {catchError, switchMap, tap, throwError} from 'rxjs';
import {AuthService} from '../services/auth.service';
import {getTrustedApiPath, isContextSelectionRequest, isPublicApiRequest, isSessionRefreshRequest} from './api-paths';
import {isLocallyHandledUnauthorized, SKIP_SESSION_REFRESH} from './auth-error-context';

export const authInterceptor: HttpInterceptorFn = (req, next) => {
  const apiPath = getTrustedApiPath(req.url);
  if (apiPath === null) {
    return next(req);
  }

  const auth = inject(AuthService);
  const token = auth.token();
  // Pierwszy wybór instytucji korzysta z ciasteczka PRE_AUTH. Zmiana instytucji korzysta z tokenu bieżącej sesji.
  const usesSession = !isPublicApiRequest(apiPath) || (isContextSelectionRequest(apiPath) && !!token);
  const handlesIpDenial = usesSession || isSessionRefreshRequest(apiPath);
  const withToken = (value: string) => req.clone({setHeaders: {Authorization: `Bearer ${value}`}});
  const send: HttpHandlerFn = (request) => next(request).pipe(tap({
    error: (error: HttpErrorResponse) => {
      if (handlesIpDenial && isIpAccessDenied(error)) {
        auth.handleIpAccessDenied();
      }
    },
  }));

  return send(usesSession && token ? withToken(token) : req).pipe(
    catchError((err: HttpErrorResponse) => {
      if (err.status !== 401 || !usesSession || isLocallyHandledUnauthorized(req, err) || req.context.get(SKIP_SESSION_REFRESH)) {
        return throwError(() => err);
      }

      // Jeśli inne żądanie już odświeżyło sesję, ponawiamy żądanie z aktualnym tokenem.
      const currentToken = auth.token();
      if (currentToken && currentToken !== token) {
        return send(withToken(currentToken));
      }
      if (token && !currentToken) {
        return throwError(() => err);
      }

      return auth.refreshOnce().pipe(
        switchMap(() => {
          const newToken = auth.token();
          return newToken ? send(withToken(newToken)) : throwError(() => err);
        })
      );
    })
  );
};

function isIpAccessDenied(error: HttpErrorResponse): boolean {
  return error.status === 403 &&
    typeof error.error === 'object' &&
    error.error !== null &&
    'code' in error.error &&
    error.error.code === 'IP_ACCESS_DENIED';
}
