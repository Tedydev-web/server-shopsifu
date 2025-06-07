import { Module, forwardRef } from '@nestjs/common'
import { PasswordController } from './password.controller'
import { PasswordService } from './password.service'
import { AuthSharedModule } from '../../shared/auth-shared.module'
import { CoreModule } from '../core/core.module'
import { AuthVerificationService } from 'src/shared/services/auth-verification.service'
import { AuthVerificationModule } from 'src/shared/services/auth-verification.module'

@Module({
  imports: [AuthSharedModule, AuthVerificationModule, forwardRef(() => CoreModule)],
  controllers: [PasswordController],
  providers: [PasswordService],
  exports: [PasswordService]
})
export class PasswordModule {}
