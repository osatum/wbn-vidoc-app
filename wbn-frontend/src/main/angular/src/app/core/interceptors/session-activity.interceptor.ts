import { inject } from '@angular/core';
import { HttpEvent, HttpInterceptorFn, HttpResponse } from '@angular/common/http';
import { catchError, map, mergeMap, of } from 'rxjs';
import { AuthService } from '../services/auth.service';
import { SESSION_REFRESH_THRESHOLD_SECONDS, SessionActivityService } from '../services/session-activity.service';
import { getTrustedApiPath, isPublicApiRequest } from './api-paths';
import { DISABLE_NAVIGATION_AUDIT } from '../services/navigation-audit.service';

const NAVIGATION_AUDIT_BATCH_PATH = '/api/navigation-audit/events/batch';

export const sessionActivityInterceptor: HttpInterceptorFn = (req, next) => {
  const apiPath = getTrustedApiPath(req.url);
  if (apiPath === null) {
    return next(req);
  }

  const auth = inject(AuthService);
  const sessionActivity = inject(SessionActivityService);
  const isPublicApi = isPublicApiRequest(apiPath);
  // Telemetria wysyłana w tle nie powinna podtrzymywać sesji użytkownika.
  const isNavigationAuditRequest =
    req.context.get(DISABLE_NAVIGATION_AUDIT) || apiPath === NAVIGATION_AUDIT_BATCH_PATH;

  return next(req).pipe(
    mergeMap((event: HttpEvent<unknown>) => {
      if (!(event instanceof HttpResponse) || isPublicApi || isNavigationAuditRequest) {
        return of(event);
      }

      sessionActivity.markBackendActivity();

      const secondsUntilExpiration = sessionActivity.secondsUntilTokenExpiration(auth.token());
      if (
        secondsUntilExpiration === null ||
        secondsUntilExpiration <= 0 ||
        secondsUntilExpiration > SESSION_REFRESH_THRESHOLD_SECONDS
      ) {
        return of(event);
      }

      return auth.refreshOnce().pipe(
        map(() => event),
        catchError(() => of(event)),
      );
    }),
  );
};
