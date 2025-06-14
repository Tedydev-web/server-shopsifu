import { Body, Controller, HttpCode, HttpStatus, Logger, Post, Req, Res, Inject, Get } from '@nestjs/common'
import { Request, Response } from 'express'
import { Throttle } from '@nestjs/throttler'

// Services
import { CoreService } from '../services/core.service'
import { UserService } from 'src/routes/user/user.service'

// DTOs & Types
import { CompleteRegistrationDto, InitiateRegistrationDto, LoginDto } from '../dtos/core.dto'
import { ICookieService } from 'src/routes/auth/auth.types'
import { ActiveUserData } from 'src/shared/types/active-user.type'

// Constants & Enums
import { CookieNames } from 'src/routes/auth/auth.constants'
import { COOKIE_SERVICE } from 'src/shared/constants/injection.tokens'
import { ALL_PERMISSIONS } from 'src/shared/constants/permissions.constants'

// Decorators
import { UserAgent } from 'src/shared/decorators/user-agent.decorator'
import { Ip } from 'src/shared/decorators/ip.decorator'
import { ActiveUser } from 'src/shared/decorators/active-user.decorator'
import { Auth, IsPublic } from 'src/shared/decorators/auth.decorator'

// Errors
import { AuthError } from 'src/routes/auth/auth.error'
import { Action, CaslAbilityFactory } from 'src/shared/providers/casl/casl-ability.factory'

@Controller('auth')
export class CoreController {
  private readonly logger = new Logger(CoreController.name)

  constructor(
    private readonly coreService: CoreService,
    private readonly userService: UserService,
    private readonly caslAbilityFactory: CaslAbilityFactory,
    @Inject(COOKIE_SERVICE) private readonly cookieService: ICookieService
  ) {}

  @Throttle({ default: { limit: 5, ttl: 60000 } })
  @IsPublic()
  @Post('initiate-registration')
  @HttpCode(HttpStatus.OK)
  async initiateRegistration(
    @Body() body: InitiateRegistrationDto,
    @Ip() ip: string,
    @UserAgent() userAgent: string,
    @Res({ passthrough: true }) res: Response
  ): Promise<any> {
    return this.coreService.initiateRegistration(body.email, ip, userAgent, res)
  }

  @Throttle({ default: { limit: 5, ttl: 60000 } })
  @IsPublic()
  @Post('complete-registration')
  @HttpCode(HttpStatus.CREATED)
  async completeRegistration(
    @Body() body: CompleteRegistrationDto,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response
  ): Promise<any> {
    const sltCookie = req.cookies[CookieNames.SLT_TOKEN]
    if (!sltCookie) {
      throw AuthError.SLTCookieMissing()
    }

    const result = await this.coreService.completeRegistrationWithSlt(
      sltCookie,
      body,
      req.ip,
      req.headers['user-agent']
    )

    // Xóa cookie sau khi hoàn tất
    this.cookieService.clearSltCookie(res)

    return result
  }

  @Throttle({ default: { limit: 5, ttl: 60000 } })
  @IsPublic()
  @Post('login')
  @HttpCode(HttpStatus.OK)
  async login(
    @Body() body: LoginDto,
    @Ip() ip: string,
    @UserAgent() userAgent: string,
    @Res({ passthrough: true }) res: Response
  ) {
    console.log(`[CoreController.login] IP: "${ip}", UserAgent: "${userAgent}", Body:`, body)
    return this.coreService.initiateLogin(body, ip, userAgent, res)
  }

  @Throttle({ default: { limit: 10, ttl: 60000 } })
  @IsPublic()
  @Post('refresh-token')
  @HttpCode(HttpStatus.OK)
  async refreshToken(
    @UserAgent() userAgent: string,
    @Ip() ip: string,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response
  ): Promise<any> {
    const deviceInfo = {
      ipAddress: ip,
      userAgent
    }
    return this.coreService.refreshToken(req, deviceInfo, res)
  }

  @Auth()
  @Get('ui-capabilities')
  @HttpCode(HttpStatus.OK)
  async getUICapabilities(
    @ActiveUser() user: ActiveUserData
  ): Promise<{ message: string; data: { permissions: Record<string, Record<string, boolean>> } }> {
    const userPermissions = await this.userService.getUserPermissions(user.id)
    const ability = await this.caslAbilityFactory.createForUser(user, userPermissions)

    const capabilities: Record<string, Record<string, boolean>> = {}

    for (const permDef of ALL_PERMISSIONS) {
      const { subject, action } = permDef
      const actionEnum = this.mapToActionEnum(action)

      if (ability.can(actionEnum, subject as any)) {
        if (!capabilities[subject]) {
          capabilities[subject] = {}
        }
        capabilities[subject][action] = true
      }
    }

    return {
      message: 'UI capabilities fetched successfully',
      data: { permissions: capabilities }
    }
  }

  private mapToActionEnum(action: string): Action {
    // Direct mapping for custom actions
    switch (action) {
      case 'read:own':
        return Action.ReadOwn
      case 'update:own':
        return Action.UpdateOwn
      case 'delete:own':
        return Action.DeleteOwn
    }
    // General mapping for standard CRUD
    const actionKey = action.charAt(0).toUpperCase() + action.slice(1)
    if (actionKey in Action) {
      return Action[actionKey as keyof typeof Action]
    }
    // Fallback for actions like 'manage'
    return action as Action
  }

  @Auth()
  @Post('logout')
  @HttpCode(HttpStatus.OK)
  async logout(
    @ActiveUser() activeUser: ActiveUserData,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response
  ): Promise<any> {
    return this.coreService.logout(activeUser.id, activeUser.sessionId, req, res)
  }
}
