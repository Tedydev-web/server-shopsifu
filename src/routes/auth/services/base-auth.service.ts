import { Injectable, Logger } from '@nestjs/common'
import { PrismaService } from 'src/shared/services/prisma.service'
import { AuthRepository } from '../auth.repo'
import { SharedUserRepository } from '../repositories/shared-user.repo'
import { HashingService } from 'src/shared/services/hashing.service'
import { TokenService } from '../providers/token.service'
import { EmailService } from '../providers/email.service'
import { TwoFactorService } from '../providers/2fa.service'
import { AuditLogService } from 'src/routes/audit-log/audit-log.service'
import { OtpService } from '../providers/otp.service'
import { DeviceService } from '../providers/device.service'
import { RolesService } from '../roles.service'

@Injectable()
export class BaseAuthService {
  protected readonly logger: Logger

  constructor(
    protected readonly prismaService: PrismaService,
    protected readonly hashingService: HashingService,
    protected readonly rolesService: RolesService,
    protected readonly authRepository: AuthRepository,
    protected readonly sharedUserRepository: SharedUserRepository,
    protected readonly emailService: EmailService,
    protected readonly tokenService: TokenService,
    protected readonly twoFactorService: TwoFactorService,
    protected readonly auditLogService: AuditLogService,
    protected readonly otpService: OtpService,
    protected readonly deviceService: DeviceService
  ) {
    this.logger = new Logger(this.constructor.name)
  }
}
