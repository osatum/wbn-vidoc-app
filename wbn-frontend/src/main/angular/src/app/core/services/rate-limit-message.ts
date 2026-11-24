import { HttpErrorResponse } from '@angular/common/http';
import { TranslocoService } from '@jsverse/transloco';

export function rateLimitMessage(error: HttpErrorResponse, transloco: TranslocoService): string {
  // Bez poprawnej liczby sekund w nagłówku Retry-After pokazujemy ogólny komunikat o limicie.
  const seconds = Number(error.headers.get('Retry-After'));
  return Number.isSafeInteger(seconds) && seconds > 0
    ? transloco.translate('common.rateLimitRetryAfter', { seconds })
    : transloco.translate('common.rateLimit');
}
