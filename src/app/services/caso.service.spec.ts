import { TestBed } from '@angular/core/testing';

import { CasoService } from './caso.service';

describe('CasoService', () => {
  let service: CasoService;

  beforeEach(() => {
    TestBed.configureTestingModule({});
    service = TestBed.inject(CasoService);
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });
});
