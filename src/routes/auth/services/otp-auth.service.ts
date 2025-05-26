import { Injectable, Logger, HttpStatus, Res } from '@nestjs/common'
import { TypeOfVerificationCode, TypeOfVerificationCodeType } from '../constants/auth.constants'
import { TokenService } from '../providers/token.service'
import { OtpService, SltContextData } from '../providers/otp.service'
import { VerifyCodeBodyType, SendOTPBodyType } from '../auth.model'
import { I18nContext, I18nService } from 'nestjs-i18n'
import { AuditLogService, AuditLogStatus } from 'src/routes/audit-log/audit-log.service'
import { ApiException } from 'src/shared/exceptions/api.exception'
import { Response } from 'express'
import envConfig from 'src/shared/config'
import { CookieNames } from 'src/shared/constants/auth.constant'
import { Prisma } from '@prisma/client'

@Injectable()
export class OtpAuthService {
  private readonly logger = new Logger(OtpAuthService.name)

  constructor(
    private readonly otpService: OtpService,
    private readonly tokenService: TokenService,
    private readonly i18nService: I18nService,
    private readonly auditLogService: AuditLogService
  ) {}

  async sendOTP(body: SendOTPBodyType & { ipAddress: string; userAgent: string }, res: Response) {
    const { email, type, ipAddress, userAgent } = body
    let sltToken: string

    if (type === TypeOfVerificationCode.REGISTER || type === TypeOfVerificationCode.RESET_PASSWORD) {
      sltToken = await this.otpService.sendOtpAndInitiateSltForAnonymous({
        email,
        purpose: type,
        ipAddress,
        userAgent,
        metadata: { sendReason: 'user_request' }
      })
      const sltCookieConfig = envConfig.cookie.sltToken
      res.cookie(sltCookieConfig.name, sltToken, {
        httpOnly: sltCookieConfig.httpOnly,
        secure: sltCookieConfig.secure,
        sameSite: sltCookieConfig.sameSite,
        maxAge: sltCookieConfig.maxAge,
        path: sltCookieConfig.path,
        domain: sltCookieConfig.domain
      })
    } else {
      this.logger.warn(
        `[OtpAuthService sendOTP] Received type '${type}' which is not handled for anonymous SLT flow. OTP will be sent without SLT cookie.`
      )
      await this.otpService.sendOTP(email, type)
    }

    const message = await this.i18nService.translate('error.Auth.Otp.SentSuccessfully', {
      lang: I18nContext.current()?.lang || 'en'
    })
    return { message }
  }

  async verifyCode(body: VerifyCodeBodyType & { userAgent: string; ip: string; sltCookie?: string }) {
    const { email, code, type, userAgent, ip, sltCookie } = body
    this.logger.debug(
      `[OtpAuthService] verifyCode called. Email: ${email}, Type: ${type}, SLT Cookie Provided: ${!!sltCookie}`
    )

    const auditInitialDetails: Prisma.JsonObject = {
      emailProvided: email,
      otpTypeProvided: type,
      ipAddress: ip,
      userAgent,
      sltCookieProvided: !!sltCookie
    }

    if (!sltCookie) {
      this.logger.warn(`verifyCode called for type ${type} without SLT cookie.`)
      this.auditLogService.recordAsync({
        action: 'VERIFY_CODE_FAIL_NO_SLT',
        status: AuditLogStatus.FAILURE,
        userEmail: email,
        ipAddress: ip,
        userAgent,
        errorMessage: 'Missing SLT cookie for code verification.',
        details: auditInitialDetails
      })
      throw new ApiException(HttpStatus.BAD_REQUEST, 'ValidationError', 'Error.Auth.OtpToken.Invalid')
    }

    const sltContext = await this.otpService.validateSltFromCookieAndGetContext(sltCookie, ip, userAgent, type)

    const emailToVerify = sltContext.email || email
    if (!emailToVerify) {
      this.logger.error(
        `[OtpAuthService verifyCode] Email for OTP verification could not be determined. SLT context email: ${sltContext.email}, body email: ${email}`
      )
      this.auditLogService.recordAsync({
        action: 'VERIFY_CODE_FAIL_NO_EMAIL',
        status: AuditLogStatus.FAILURE,
        ipAddress: ip,
        userAgent,
        errorMessage: 'Email is required for OTP verification and could not be determined.',
        details: { ...auditInitialDetails, sltContextJti: sltContext.sltJti } as Prisma.JsonObject
      })
      throw new ApiException(HttpStatus.BAD_REQUEST, 'ValidationError', 'Error.Auth.Email.NotFound')
    }

    if (sltContext.email && email && sltContext.email !== email) {
      this.logger.warn(
        `[OtpAuthService verifyCode] Email mismatch. SLT context: ${sltContext.email}, body: ${email}. Using SLT context email.`
      )
      this.auditLogService.recordAsync({
        action: 'VERIFY_CODE_EMAIL_MISMATCH',
        status: AuditLogStatus.FAILURE,
        userId: sltContext.userId !== null ? sltContext.userId : undefined,
        userEmail: sltContext.email,
        ipAddress: ip,
        userAgent,
        errorMessage: 'Email in request body does not match email in session token.',
        details: {
          ...auditInitialDetails,
          bodyEmailProvided: email,
          sltEmailInContext: sltContext.email,
          sltJti: sltContext.sltJti
        } as Prisma.JsonObject
      })
    }

    await this.otpService.verifyOtpOnly(
      emailToVerify,
      code,
      type,
      sltContext.userId !== null ? sltContext.userId : undefined,
      ip,
      userAgent
    )

    const marked = await this.otpService.markSltOtpAsVerified(sltContext.sltJti)
    if (!marked) {
      this.logger.error(
        `[OtpAuthService verifyCode] Failed to mark OTP as verified in SLT context for JTI ${sltContext.sltJti}.`
      )
      this.auditLogService.recordAsync({
        action: 'VERIFY_CODE_FAIL_MARK_OTP',
        status: AuditLogStatus.FAILURE,
        userId: sltContext.userId !== null ? sltContext.userId : undefined,
        userEmail: emailToVerify,
        ipAddress: ip,
        userAgent,
        errorMessage: 'Failed to update session state after OTP verification. Please try again.',
        details: {
          ...auditInitialDetails,
          sltJti: sltContext.sltJti,
          reason: 'markSltOtpAsVerified_failed'
        } as Prisma.JsonObject
      })
      throw new ApiException(HttpStatus.INTERNAL_SERVER_ERROR, 'InternalServerError', 'Error.Global.Unknown')
    }

    const finalAuditDetails: Prisma.JsonObject = {
      ...auditInitialDetails,
      sltJti: sltContext.sltJti,
      sltPurpose: sltContext.purpose,
      sltUserId: sltContext.userId,
      emailVerifiedWith: emailToVerify
    }

    this.auditLogService.recordAsync({
      action: 'VERIFY_CODE_SUCCESS',
      userId: sltContext.userId !== null ? sltContext.userId : undefined,
      userEmail: emailToVerify,
      status: AuditLogStatus.SUCCESS,
      ipAddress: ip,
      userAgent,
      details: finalAuditDetails
    })

    return { message: 'Auth.Otp.VerifiedSuccessfully' }
  }
}
