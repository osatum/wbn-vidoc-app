import { HttpErrorResponse, HttpHeaders } from '@angular/common/http';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { TranslocoService } from '@jsverse/transloco';
import { of, throwError } from 'rxjs';

import { AuthService } from '../../../core/services/auth.service';
import { RedirectService } from '../../../core/services/redirect-service';
import { ToastService } from '../../../core/services/toast-service';
import { translocoTestingModule } from '../../../testing/transloco-testing-module';
import { LoginPage } from './login-page';

describe('LoginPage', () => {
  let component: LoginPage;
  let fixture: ComponentFixture<LoginPage>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [LoginPage, translocoTestingModule],
      providers: [
        provideRouter([]),
        {
          provide: AuthService,
          useValue: {
            getPendingInstitutionsSnapshot: vi.fn(() => null),
            login: vi.fn(() => of({})),
          },
        },
        { provide: RedirectService, useValue: { redirectAfterLogin: vi.fn() } },
        { provide: ToastService, useValue: { show: vi.fn() } },
      ],
    })
    .compileComponents();

    fixture = TestBed.createComponent(LoginPage);
    component = fixture.componentInstance;
    await fixture.whenStable();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });

  it('shows the wait time after the backend throttles login', () => {
    TestBed.inject(TranslocoService).setTranslation({
      common: { rateLimitRetryAfter: 'Spróbuj ponownie za {{seconds}} s.' },
    }, 'pl');
    vi.mocked(TestBed.inject(AuthService).login).mockReturnValueOnce(throwError(() => new HttpErrorResponse({
      status: 429,
      headers: new HttpHeaders({ 'Retry-After': '30' }),
      error: { code: 'RATE_LIMITED' },
    })));
    component.loginForm.setValue({ email: 'user@example.test', password: 'wrong-password' });

    component.onSubmit();

    expect(component.errorMessage()).toBe('Spróbuj ponownie za 30 s.');
    expect(TestBed.inject(RedirectService).redirectAfterLogin).not.toHaveBeenCalled();
  });
});
