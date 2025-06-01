import { Injectable, Logger } from '@nestjs/common'
import { Response } from 'express'
import { OtpService } from '../providers/otp.service'
import { TokenService } from '../providers/token.service'
import { MaxVerificationAttemptsExceededException } from '../auth.error'
import { ApiException } from 'src/shared/exceptions/api.exception'
import { TypeOfVerificationCode } from '../constants/auth.constants'
import envConfig from 'src/shared/config'

@Injectable()
export class SltHelperService {
  private readonly logger = new Logger(SltHelperService.name)

  constructor(
    private readonly otpService: OtpService,
    private readonly tokenService: TokenService
  ) {}

  /**
   * Helper method to set SLT cookie in a standardized way
   * @param res Express Response object
   * @param sltJwt JWT token for SLT
   * @param purpose Purpose of SLT for logging
   */
  setSltCookie(res: Response, sltJwt: string, purpose: TypeOfVerificationCode): void {
    const sltCookieConfig = envConfig.cookie.sltToken
    if (sltCookieConfig && sltJwt) {
      res.cookie(sltCookieConfig.name, sltJwt, {
        path: sltCookieConfig.path,
        domain: sltCookieConfig.domain,
        maxAge: sltCookieConfig.maxAge,
        httpOnly: sltCookieConfig.httpOnly,
        secure: sltCookieConfig.secure,
        sameSite: sltCookieConfig.sameSite as 'lax' | 'strict' | 'none' | boolean
      })
    }
  }

  async handleSltAttemptIncrementAndFinalization(
    sltJti: string,
    maxAttempts: number,
    errorContext: string,
    res?: Response
  ): Promise<void> {
    try {
      const newAttempts = await this.otpService.incrementSltAttempts(sltJti)

      if (newAttempts >= maxAttempts) {
        await this.otpService.finalizeSlt(sltJti)
        if (res) this.tokenService.clearSltCookie(res)
        throw new MaxVerificationAttemptsExceededException()
      }
    } catch (incrementError) {
      if (
        incrementError instanceof MaxVerificationAttemptsExceededException ||
        (incrementError instanceof ApiException && incrementError.errorCode === 'error.Error.Auth.SltContext.Finalized')
      ) {
        if (res && !(incrementError instanceof MaxVerificationAttemptsExceededException)) {
          this.tokenService.clearSltCookie(res)
        }

        throw incrementError
      }

      await this.otpService.finalizeSlt(sltJti).catch((ef) => {})
      if (res) this.tokenService.clearSltCookie(res)

      throw incrementError
    }
  }
}
