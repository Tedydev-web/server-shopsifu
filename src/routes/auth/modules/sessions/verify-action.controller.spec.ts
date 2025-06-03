import { Test, TestingModule } from '@nestjs/testing';
import { VerifyActionController } from './verify-action.controller';

describe('VerifyActionController', () => {
  let controller: VerifyActionController;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [VerifyActionController],
    }).compile();

    controller = module.get<VerifyActionController>(VerifyActionController);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });
});
