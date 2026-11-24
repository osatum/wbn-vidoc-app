import { TestBed } from '@angular/core/testing';
import { ActivatedRouteSnapshot, provideRouter, RouterStateSnapshot } from '@angular/router';
import { firstValueFrom, isObservable, of } from 'rxjs';
import { UserProfileResponse } from '../backend';
import { AuthService } from '../services/auth.service';
import { systemOperatorGuard } from './system-operator-guard';

describe('systemOperatorGuard', () => {
  const { InstitutionTypeEnum, InstitutionRoleEnum } = UserProfileResponse;
  let profile: UserProfileResponse | null;

  beforeEach(() => {
    profile = null;
    TestBed.configureTestingModule({
      providers: [
        provideRouter([]),
        { provide: AuthService, useValue: {
          getUserProfile: () => of(profile),
          silentRefresh: () => of(false),
        } },
      ],
    });
  });

  function checkAccess() {
    const result = TestBed.runInInjectionContext(() =>
      systemOperatorGuard(new ActivatedRouteSnapshot(), {} as RouterStateSnapshot));
    return isObservable(result) ? firstValueFrom(result) : result;
  }

  it('allows an administrator in operator context', async () => {
    profile = {
      institutionType: InstitutionTypeEnum.SystemOperator,
      institutionRole: InstitutionRoleEnum.InstitutionAdmin,
    };
    expect(await checkAccess()).toBe(true);
  });

  it('denies an administrator in research-unit context', async () => {
    profile = {
      institutionType: InstitutionTypeEnum.ResearchUnit,
      institutionRole: InstitutionRoleEnum.InstitutionAdmin,
    };
    expect((await checkAccess()).toString()).toBe('/institution/user/denied');
  });

  it('redirects an operator without the administrator role outside the protected routes', async () => {
    profile = {
      institutionType: InstitutionTypeEnum.SystemOperator,
      institutionRole: InstitutionRoleEnum.InstitutionViewer,
    };
    expect((await checkAccess()).toString()).toBe('/denied');
  });
});
