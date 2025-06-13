import {
  Controller,
  Post,
  Body,
  Req,
  Res,
  HttpCode,
  HttpStatus,
  Inject,
  forwardRef,
  Logger,
  UseGuards,
  Ip
} from '@nestjs/common'
import { Request, Response } from 'express'
import { Auth, IsPublic } from 'src/shared/decorators/auth.decorator'
import { ActiveUser } from 'src/shared/decorators/active-user.decorator'
import { UserAgent } from 'src/shared/decorators/user-agent.decorator'
import { ActiveUserData } from 'src/shared/types/active-user.type'
import { TwoFactorVerifyDto } from '../dtos/two-factor.dto'
import { AuthVerificationService } from '../services/auth-verification.service'
import { TwoFactorService } from '../services/two-factor.service'
import { CookieNames, TypeOfVerificationCode } from '../auth.constants'
import { PermissionGuard } from 'src/shared/guards/permission.guard'
import { RequirePermissions } from 'src/shared/decorators/permissions.decorator'
import { TWO_FACTOR_SERVICE, COOKIE_SERVICE } from 'src/shared/constants/injection.tokens'
import { CookieService } from 'src/shared/services/cookie.service'
import { Action, AppSubject } from 'src/shared/providers/casl/casl-ability.factory'

@Auth()
@UseGuards(PermissionGuard)
@Controller('auth/2fa')
export class TwoFactorController {
  private readonly logger = new Logger(TwoFactorController.name)

  constructor(
    @Inject(TWO_FACTOR_SERVICE) private readonly twoFactorService: TwoFactorService,
    @Inject(forwardRef(() => AuthVerificationService))
    private readonly authVerificationService: AuthVerificationService,
    @Inject(COOKIE_SERVICE) private readonly cookieService: CookieService
  ) {}

  @Post('setup')
  @RequirePermissions({ action: Action.Create, subject: AppSubject.TwoFactor })
  @HttpCode(HttpStatus.OK)
  async setupTwoFactor(
    @ActiveUser() activeUser: ActiveUserData,
    @Ip() ip: string,
    @UserAgent() userAgent: string,
    @Res({ passthrough: true }) res: Response
  ): Promise<any> {
    return this.authVerificationService.initiateVerification(
      {
        userId: activeUser.id,
        deviceId: activeUser.deviceId,
        email: activeUser.email,
        ipAddress: ip,
        userAgent: userAgent,
        purpose: TypeOfVerificationCode.SETUP_2FA
      },
      res
    )
  }

  @Post('confirm-setup')
  @RequirePermissions({ action: Action.Create, subject: AppSubject.TwoFactor })
  @HttpCode(HttpStatus.OK)
  async confirmTwoFactorSetup(
    @Body() body: TwoFactorVerifyDto,
    @Ip() ip: string,
    @UserAgent() userAgent: string,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response
  ): Promise<any> {
    return this.authVerificationService.verifyCode(req.cookies[CookieNames.SLT_TOKEN], body.code, ip, userAgent, res)
  }

  @Post('verify')
  @RequirePermissions({ action: Action.Update, subject: AppSubject.TwoFactor })
  @HttpCode(HttpStatus.OK)
  async verifyTwoFactor(
    @Body() body: TwoFactorVerifyDto,
    @Ip() ip: string,
    @UserAgent() userAgent: string,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response
  ): Promise<any> {
    return this.authVerificationService.verifyCode(req.cookies[CookieNames.SLT_TOKEN], body.code, ip, userAgent, res)
  }

  @Post('disable')
  @RequirePermissions({ action: Action.Delete, subject: AppSubject.TwoFactor })
  @HttpCode(HttpStatus.OK)
  async disableTwoFactor(
    @ActiveUser() activeUser: ActiveUserData,
    @Body() body: TwoFactorVerifyDto,
    @Ip() ip: string,
    @UserAgent() userAgent: string,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response
  ): Promise<{ message: string }> {
    return this.twoFactorService.disableVerification(activeUser.id, body.code)
  }

  @Post('regenerate-recovery-codes')
  @RequirePermissions({ action: Action.Update, subject: AppSubject.TwoFactor })
  @HttpCode(HttpStatus.OK)
  async regenerateRecoveryCodes(
    @ActiveUser() activeUser: ActiveUserData,
    @Body() body: TwoFactorVerifyDto,
    @Ip() ip: string,
    @UserAgent() userAgent: string
  ): Promise<{ message: string; data: { recoveryCodes: string[] } }> {
    return this.twoFactorService.regenerateRecoveryCodes(activeUser.id, body.code, body.method, ip, userAgent)
  }
}
