import {
  Controller,
  Get,
  Post,
  Body,
  Query,
  Req,
  Res,
  HttpCode,
  HttpStatus,
  Logger,
  Inject,
  forwardRef,
  Ip
} from '@nestjs/common'
import { Request, Response } from 'express'
import { ConfigService } from '@nestjs/config'

import { SocialService } from '../services/social.service'
import { CoreService } from '../services/core.service'
import { UserAgent } from 'src/shared/decorators/user-agent.decorator'
import { ActiveUser } from 'src/shared/decorators/active-user.decorator'
import { ICookieService, ITokenService, PendingLinkTokenPayloadCreate } from 'src/routes/auth/auth.types'
import {
  GoogleAuthUrlQueryDto,
  GoogleCallbackQueryDto,
  VerifyAuthenticationDto,
  GoogleAuthUrlDataDto,
  AccountLinkingRequiredDataDto
} from '../dtos/social.dto'
import { CookieNames, TypeOfVerificationCode } from 'src/routes/auth/auth.constants'
import { Auth, IsPublic } from 'src/shared/decorators/auth.decorator'
import { AuthVerificationService } from '../services/auth-verification.service'
import { AuthError } from 'src/routes/auth/auth.error'
import { COOKIE_SERVICE, TOKEN_SERVICE } from 'src/shared/constants/injection.tokens'
import * as crypto from 'crypto'
import { ActiveUserData } from 'src/shared/types/active-user.type'

@IsPublic()
@Controller('auth/social')
export class SocialController {
  private readonly logger = new Logger(SocialController.name)

  constructor(
    private readonly socialService: SocialService,
    private readonly configService: ConfigService,
    @Inject(forwardRef(() => CoreService)) private readonly coreService: CoreService,
    @Inject(forwardRef(() => AuthVerificationService))
    private readonly authVerificationService: AuthVerificationService,
    @Inject(COOKIE_SERVICE) private readonly cookieService: ICookieService,
    @Inject(TOKEN_SERVICE) private readonly tokenService: ITokenService
  ) {}

  @IsPublic()
  @Get('google')
  @HttpCode(HttpStatus.OK)
  getGoogleAuthUrl(
    @Query() query: GoogleAuthUrlQueryDto,
    @Res({ passthrough: true }) res: Response,
    @ActiveUser() activeUser?: ActiveUserData
  ): GoogleAuthUrlDataDto {
    const nonce = crypto.randomBytes(16).toString('hex')
    const { url } = this.socialService.getGoogleAuthUrl({
      action: query.action,
      userId: activeUser?.id,
      redirectUrl: query.redirectUrl,
      nonce: nonce
    })
    this.cookieService.setOAuthNonceCookie(res, nonce)
    return { url }
  }

  @IsPublic()
  @Get('google/callback')
  @HttpCode(HttpStatus.OK)
  async googleCallback(
    @Query() query: GoogleCallbackQueryDto,
    @Res({ passthrough: true }) res: Response,
    @Req() req: Request,
    @UserAgent() userAgent: string,
    @Ip() ip: string
  ): Promise<any> {
    const { code, state, error } = query
    const originalNonce = req.cookies?.[CookieNames.OAUTH_NONCE]
    this.cookieService.clearOAuthNonceCookie(res)

    if (error) {
      throw AuthError.GoogleCallbackError({ originalError: error })
    }

    const result = await this.socialService.googleCallback({
      code,
      state,
      originalNonceFromCookie: originalNonce,
      userAgent,
      ip
    })

    if ('redirectToError' in result && result.redirectToError) {
      throw AuthError.GoogleCallbackError({ code: result.errorCode, message: result.errorMessage })
    }

    if ('needsLinking' in result && result.needsLinking) {
      const payload: PendingLinkTokenPayloadCreate = {
        existingUserId: result.existingUserId,
        googleId: result.googleId,
        googleEmail: result.googleEmail,
        googleName: result.googleName,
        googleAvatar: result.googleAvatar
      }
      const pendingLinkToken = this.tokenService.signPendingLinkToken(payload)
      this.cookieService.setOAuthPendingLinkTokenCookie(res, pendingLinkToken)

      const responseData: AccountLinkingRequiredDataDto = {
        needsLinking: true,
        existingUserEmail: result.existingUserEmail,
        googleEmail: result.googleEmail,
        googleName: result.googleName ?? null,
        googleAvatar: result.googleAvatar ?? null
      }

      return {
        message: result.message,
        data: responseData
      }
    }

    if ('user' in result && 'device' in result) {
      return this.authVerificationService.initiateVerification(
        {
          userId: result.user.id,
          deviceId: result.device.id,
          email: result.user.email,
          ipAddress: ip,
          userAgent,
          purpose: result.purpose,
          rememberMe: true,
          metadata: { from: 'google-login', isNewUser: result.isNewUser }
        },
        res
      )
    }

    throw AuthError.InternalServerError('auth.error.social.googleCallbackError')
  }

  @IsPublic()
  @Post('complete-link')
  @HttpCode(HttpStatus.OK)
  async completeLink(
    @Body() body: VerifyAuthenticationDto,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
    @Ip() ip: string,
    @UserAgent() userAgent: string
  ): Promise<any> {
    const pendingLinkToken = req.cookies?.[CookieNames.OAUTH_PENDING_LINK]
    if (!pendingLinkToken) {
      throw AuthError.PendingSocialLinkTokenMissing()
    }

    const result = await this.socialService.completeLinkAndLogin(pendingLinkToken, body.password || '', userAgent, ip)
    const { user, device } = result.data

    this.cookieService.clearOAuthPendingLinkTokenCookie(res)

    return this.coreService.finalizeLoginAndCreateTokens(user, device, true, res, ip, userAgent)
  }

  @Auth()
  @Post('unlink/google')
  @HttpCode(HttpStatus.OK)
  async initiateUnlinkGoogleAccount(
    @ActiveUser() activeUser: ActiveUserData,
    @Ip() ip: string,
    @UserAgent() userAgent: string,
    @Res({ passthrough: true }) res: Response
  ): Promise<any> {
    if (!activeUser.email) {
      throw AuthError.InternalServerError('User email not found in token payload.')
    }
    return this.authVerificationService.initiateVerification(
      {
        userId: activeUser.id,
        deviceId: activeUser.deviceId,
        email: activeUser.email,
        ipAddress: ip,
        userAgent: userAgent,
        purpose: TypeOfVerificationCode.UNLINK_GOOGLE_ACCOUNT
      },
      res
    )
  }
}
