import { DOCUMENT } from '@angular/common';
import { inject } from '@angular/core';
import { BASE_PATH } from '../backend/variables';

const PUBLIC_API_PATHS = [
  '/api/auth',
  '/api/home',
  '/api/registration',
  '/api/password-reset',
] as const;

const API_PREFIX = '/api/';

/**
 * Obsługa sesji obejmuje tylko ścieżki API pod adresem aplikacji lub skonfigurowanego backendu.
 */
export function getTrustedApiPath(url: string): string | null {
  const document = inject(DOCUMENT);
  const configuredBasePath = inject(BASE_PATH, { optional: true });

  try {
    const target = new URL(url, document.baseURI);
    if ((target.protocol !== 'https:' && target.protocol !== 'http:') || target.username || target.password) {
      return null;
    }

    if (target.origin === document.location?.origin && target.pathname.startsWith(API_PREFIX)) {
      return target.pathname;
    }

    if (configuredBasePath) {
      const backend = new URL(configuredBasePath, document.baseURI);
      const basePath = backend.pathname.replace(/\/+$/, '');
      if (target.origin === backend.origin && target.pathname.startsWith(basePath + API_PREFIX)) {
        // Usuwamy ścieżkę bazową, aby te same reguły działały dla API zamontowanego pod prefiksem.
        return target.pathname.slice(basePath.length);
      }
    }
  } catch {
    return null;
  }

  return null;
}

export function isPublicApiRequest(path: string): boolean {
  return PUBLIC_API_PATHS.some((prefix) => path === prefix || path.startsWith(prefix + '/'));
}

export function isContextSelectionRequest(path: string): boolean {
  return path === '/api/auth/select-institution';
}

export function isSessionRefreshRequest(path: string): boolean {
  return path === '/api/auth/refresh';
}
