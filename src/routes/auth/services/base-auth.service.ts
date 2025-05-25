import { Injectable, Logger } from '@nestjs/common'
import { I18nService } from 'nestjs-i18n'
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
import { RedisService } from 'src/shared/providers/redis/redis.service'
import { GeolocationService } from 'src/shared/services/geolocation.service'
import { JwtService } from '@nestjs/jwt'

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
    protected readonly deviceService: DeviceService,
    protected readonly i18nService: I18nService,
    protected readonly redisService: RedisService,
    protected readonly geolocationService: GeolocationService,
    protected readonly jwtService: JwtService
  ) {
    this.logger = new Logger(this.constructor.name)
  }
}
