import {
  Controller,
  Get,
  Post,
  Body,
  Query,
  Req,
  Res,
  Ip,
  HttpCode,
  HttpStatus,
  Logger,
  Inject,
  forwardRef
} from '@nestjs/common'
import { Request, Response } from 'express'
import { ConfigService } from '@nestjs/config'

import { SocialService } from './social.service'
import { CoreService } from 'src/routes/auth/modules/core/core.service'
import { UserAgent } from 'src/shared/decorators/user-agent.decorator'
import { ActiveUser } from 'src/shared/decorators/active-user.decorator'
import {
  ICookieService,
  ITokenService,
  AccessTokenPayload,
  PendingLinkTokenPayloadCreate
} from 'src/shared/types/auth.types'
import {
  GoogleAuthUrlQueryDto,
  GoogleCallbackQueryDto,
  VerifyAuthenticationDto,
  GoogleAuthUrlDataDto,
  AccountLinkingRequiredDataDto
} from './social.dto'
import { CookieNames, TypeOfVerificationCode } from 'src/shared/constants/auth/auth.constants'
import { Auth, IsPublic } from 'src/shared/decorators/auth.decorator'
import { AuthVerificationService } from '../../../../shared/services/auth-verification.service'
import { AuthError } from 'src/routes/auth/auth.error'
import { COOKIE_SERVICE, TOKEN_SERVICE } from 'src/shared/constants/injection.tokens'
import * as crypto from 'crypto'
import { SuccessMessage } from 'src/shared/decorators/success-message.decorator'

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
  @SuccessMessage('auth.Auth.Google.UrlGeneratedSuccess' as any)
  getGoogleAuthUrl(
    @Query() query: GoogleAuthUrlQueryDto,
    @Res({ passthrough: true }) res: Response,
    @ActiveUser() activeUser?: AccessTokenPayload
  ): GoogleAuthUrlDataDto {
    this.logger.debug(`[getGoogleAuthUrl] Getting Google auth URL for action: ${query.action}`)
    const nonce = crypto.randomBytes(16).toString('hex')
    const { url } = this.socialService.getGoogleAuthUrl({
      action: query.action,
      userId: activeUser?.userId,
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
    this.logger.debug(`[googleCallback] Received callback from Google.`)
    this.cookieService.clearOAuthNonceCookie(res)

    if (error) {
      throw AuthError.GoogleCallbackError(error)
    }

    const result = await this.socialService.googleCallback({
      code,
      state,
      originalNonceFromCookie: originalNonce,
      userAgent,
      ip
    })

    if ('redirectToError' in result && result.redirectToError) {
      throw AuthError.GoogleCallbackError(result.errorMessage)
    }

    if ('needsLinking' in result && result.needsLinking) {
      this.logger.debug(`[googleCallback] Account needs linking for Google email: ${result.googleEmail}`)
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
      this.logger.debug(`[googleCallback] Google auth successful for user ${result.user.id}. Initiating verification.`)
      // This is a successful login/registration via Google. Now, hand over to the
      // central verification service to handle 2FA or device verification if needed.
      return this.authVerificationService.initiateVerification(
        {
          userId: result.user.id,
          deviceId: result.device.id,
          email: result.user.email,
          ipAddress: ip,
          userAgent,
          purpose: result.purpose,
          rememberMe: true, // Social logins are generally "remembered"
          metadata: { from: 'google-login', isNewUser: result.isNewUser }
        },
        res
      )
    }

    // Fallback for unexpected results
    throw AuthError.InternalServerError('An unexpected error occurred during Google callback processing.')
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

    this.logger.debug(`[completeLink] Attempting to complete social account linking.`)

    const { user, device } = await this.socialService.completeLinkAndLogin(
      pendingLinkToken,
      body.password || '',
      userAgent,
      ip
    )

    this.cookieService.clearOAuthPendingLinkTokenCookie(res)

    this.logger.log(`[completeLink] Social account linked successfully for user ${user.id}. Finalizing login.`)
    // After linking, finalize the login to create session and tokens
    return this.coreService.finalizeLoginAndCreateTokens(user, device, true, res, ip, userAgent)
  }

  @Auth()
  @Post('unlink/google')
  @HttpCode(HttpStatus.OK)
  async initiateUnlinkGoogleAccount(
    @ActiveUser() activeUser: AccessTokenPayload,
    @Ip() ip: string,
    @UserAgent() userAgent: string,
    @Res({ passthrough: true }) res: Response
  ): Promise<any> {
    this.logger.debug(`[initiateUnlinkGoogleAccount] User ${activeUser.userId} initiating Google account unlinking.`)
    if (!activeUser.email) {
      // This should ideally not happen if token payload is correct
      throw AuthError.InternalServerError('Email is required for this action.')
    }
    // This will start the verification flow (e.g., send OTP).
    // The user must then call a verification endpoint (e.g., /auth/otp/verify)
    // which will complete the unlinking process via AuthVerificationService.
    return this.authVerificationService.initiateVerification(
      {
        userId: activeUser.userId,
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
