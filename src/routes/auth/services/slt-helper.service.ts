import { Injectable, Logger } from '@nestjs/common'
import { Response } from 'express'
import { AuditLogData } from 'src/routes/audit-log/audit-log.service'
import { Prisma } from '@prisma/client'
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
      this.logger.debug(`SLT token cookie (${sltCookieConfig.name}) set for ${purpose}.`)
    } else {
      this.logger.warn(`SLT cookie configuration or SLT JWT missing for ${purpose}. Cookie not set.`)
    }
  }

  async handleSltAttemptIncrementAndFinalization(
    sltJti: string,
    maxAttempts: number,
    errorContext: string,
    auditLogEntry: Partial<AuditLogData> & { details: Prisma.JsonObject },
    res?: Response
  ): Promise<void> {
    try {
      const newAttempts = await this.otpService.incrementSltAttempts(sltJti)
      this.logger.log(
        `SLT attempts for JTI ${sltJti} (context: ${errorContext}) incremented to ${newAttempts}/${maxAttempts}`
      )
      if (auditLogEntry.details && typeof auditLogEntry.details === 'object') {
        auditLogEntry.details.sltAttemptsAfterIncrement = newAttempts
      }

      if (newAttempts >= maxAttempts) {
        this.logger.warn(`Max attempts reached for SLT JTI ${sltJti} (context: ${errorContext}). Finalizing.`)
        await this.otpService.finalizeSlt(sltJti)
        if (res) this.tokenService.clearSltCookie(res)
        if (auditLogEntry.details && typeof auditLogEntry.details === 'object') {
          auditLogEntry.details.sltFinalizedByHelperMaxAttempts = true
        }
        throw new MaxVerificationAttemptsExceededException()
      }
    } catch (incrementError) {
      this.logger.error(
        `Error during SLT attempt increment/finalization for JTI ${sltJti} (context: ${errorContext}): ${incrementError.message}`
      )
      if (auditLogEntry.details && typeof auditLogEntry.details === 'object') {
        auditLogEntry.details.sltHelperIncrementError = incrementError.message
      }

      if (
        incrementError instanceof MaxVerificationAttemptsExceededException ||
        (incrementError instanceof ApiException && incrementError.errorCode === 'error.Error.Auth.SltContext.Finalized')
      ) {
        if (res && !(incrementError instanceof MaxVerificationAttemptsExceededException)) {
          this.tokenService.clearSltCookie(res)
          if (auditLogEntry.details && typeof auditLogEntry.details === 'object') {
            auditLogEntry.details.sltCookieClearedByHelperFinalized = true
          }
        }

        if (
          auditLogEntry.details &&
          typeof auditLogEntry.details === 'object' &&
          incrementError instanceof ApiException &&
          incrementError.errorCode === 'error.Error.Auth.SltContext.Finalized'
        ) {
          auditLogEntry.details.sltFinalizedByHelperContextFinalized = true
        }
        throw incrementError
      }

      this.logger.warn(`Unexpected error during SLT increment for ${sltJti}. Finalizing SLT.`)
      await this.otpService
        .finalizeSlt(sltJti)
        .catch((ef) =>
          this.logger.error(
            `Error finalizing SLT ${sltJti} after non-specific increment error in ${errorContext}: ${ef.message}`
          )
        )
      if (res) this.tokenService.clearSltCookie(res)
      if (auditLogEntry.details && typeof auditLogEntry.details === 'object') {
        auditLogEntry.details.sltFinalizedByHelperGenericIncrementError = true
        auditLogEntry.details.sltCookieClearedByHelperGenericIncrementError = !!res
      }

      throw incrementError
    }
  }
}
