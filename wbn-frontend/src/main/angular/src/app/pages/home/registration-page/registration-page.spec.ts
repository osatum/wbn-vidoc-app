import {ComponentFixture, TestBed} from '@angular/core/testing';
import {ActivatedRoute, convertToParamMap, provideRouter} from '@angular/router';
import {HttpErrorResponse, HttpHeaders} from '@angular/common/http';
import {of, throwError} from 'rxjs';
import {TranslocoTestingModule} from '@jsverse/transloco';

import {RegistrationService} from '../../../core/backend';
import {RegistrationPage} from './registration-page';

const translocoTestingModule = TranslocoTestingModule.forRoot({
  langs: {
    pl: {
      page: {
        home: {
          registration: {
            'no-institutions': 'Instytucje dostępne do rejestracji nie są obecnie dostępne.',
            'success': 'Formularz rejestracji został przyjęty.',
          },
        },
      },
      common: {
        serverError: 'Wystąpił błąd serwera ({{status}}). Spróbuj ponownie później.',
        connectionError: 'Nie można połączyć się z serwerem. Sprawdź połączenie i spróbuj ponownie.',
        rateLimitRetryAfter: 'Zbyt wiele prób. Spróbuj ponownie za {{seconds}} s.',
      },
    },
  },
  translocoConfig: {
    availableLangs: ['pl'],
    defaultLang: 'pl',
    reRenderOnLangChange: true,
    prodMode: true,
  },
  preloadLangs: true,
});

describe('RegistrationPage', () => {
  let component: RegistrationPage;
  let fixture: ComponentFixture<RegistrationPage>;
  let registrationService: {
    findGeneralRegistrationInstitutions: ReturnType<typeof vi.fn>;
    validateRegistrationStart: ReturnType<typeof vi.fn>;
    submitRegistration: ReturnType<typeof vi.fn>;
  };

  beforeEach(async () => {
    registrationService = {
      findGeneralRegistrationInstitutions: vi.fn(() => of([])),
      validateRegistrationStart: vi.fn(() => of({allowed: true, institution: {id: 1, name: 'Jednostka'}})),
      submitRegistration: vi.fn(() => of({status: 'ACCEPTED'})),
    };

    await TestBed.configureTestingModule({
      imports: [RegistrationPage, translocoTestingModule],
      providers: [
        provideRouter([]),
        {
          provide: ActivatedRoute,
          useValue: {
            snapshot: {
              paramMap: convertToParamMap({}),
            },
          },
        },
        {
          provide: RegistrationService,
          useValue: registrationService,
        },
      ],
    }).compileComponents();

    fixture = TestBed.createComponent(RegistrationPage);
    component = fixture.componentInstance;
    fixture.detectChanges();
    await fixture.whenStable();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });

  it('should hide registration fields when no institutions are available', () => {
    expect(component.errorMessage()).toContain('Instytucje dostępne do rejestracji');
    expect(fixture.nativeElement.querySelector('#email')).toBeNull();
    expect(fixture.nativeElement.querySelector('#password')).toBeNull();
  });

  it('shows the wait time when registration reaches the request limit', async () => {
    registrationService.submitRegistration.mockReturnValueOnce(throwError(() => new HttpErrorResponse({
      status: 429,
      headers: new HttpHeaders({'Retry-After': '90'}),
      error: {code: 'RATE_LIMITED'},
    })));
    selectInstitution();
    fillValidForm('jan@example.edu');

    component.onSubmit();
    fixture.detectChanges();
    await fixture.whenStable();

    expect(component.success()).toBe(false);
    expect(component.errorMessage()).toBe('Zbyt wiele prób. Spróbuj ponownie za 90 s.');
    expect(component.fieldError('email')).toBeNull();
  });

  it('should show server status for 500 response', async () => {
    registrationService.submitRegistration.mockReturnValueOnce(throwError(() => new HttpErrorResponse({
      status: 500,
      statusText: 'Internal Server Error',
    })));
    selectInstitution();
    fillValidForm('jan@example.edu');

    component.onSubmit();
    fixture.detectChanges();
    await fixture.whenStable();

    expect(component.errorMessage()).toContain('błąd serwera (500)');
  });

  it('should require registration consents before submit', () => {
    selectInstitution();
    component.registrationForm.setValue({
      firstName: 'Jan',
      lastName: 'Kowalski',
      email: 'jan@example.edu',
      orcid: '',
      password: 'secret123',
      termsAndPrivacyPolicyAccepted: false,
      personalDataProcessingAcknowledged: false,
    });

    component.onSubmit();

    expect(registrationService.submitRegistration).not.toHaveBeenCalled();
    expect(component.isInvalid('termsAndPrivacyPolicyAccepted')).toBe(true);
    expect(component.isInvalid('personalDataProcessingAcknowledged')).toBe(true);
  });

  it('should include registration consents in submit payload', () => {
    selectInstitution();
    fillValidForm('jan@example.edu');

    component.onSubmit();

    expect(registrationService.submitRegistration).toHaveBeenCalledWith(1, expect.objectContaining({
      termsAndPrivacyPolicyAccepted: true,
      personalDataProcessingAcknowledged: true,
    }));
  });

  function selectInstitution(): void {
    component.selectedInstitution.set({id: 1, name: 'Jednostka'});
    component.selectedInstitutionId.set(1);
    fixture.detectChanges();
  }

  function fillValidForm(email: string): void {
    component.registrationForm.setValue({
      firstName: 'Jan',
      lastName: 'Kowalski',
      email,
      orcid: '',
      password: 'secret123',
      termsAndPrivacyPolicyAccepted: true,
      personalDataProcessingAcknowledged: true,
    });
  }
});
