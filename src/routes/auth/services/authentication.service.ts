import { Injectable } from '@nestjs/common'
import { BaseAuthService } from './base-auth.service'
import { LoginBodyType, RegisterBodyType } from 'src/routes/auth/auth.model'
import { Response, Request } from 'express'
import {
  AbsoluteSessionLifetimeExceededException,
  DeviceMismatchException,
  DeviceSetupFailedException,
  EmailAlreadyExistsException,
  EmailNotFoundException,
  InvalidPasswordException
} from 'src/routes/auth/auth.error'
import { AuditLogData, AuditLogStatus } from 'src/routes/audit-log/audit-log.service'
import { isUniqueConstraintPrismaError } from 'src/shared/utils/type-guards.utils'
import { ApiException } from 'src/shared/exceptions/api.exception'
import { AccessTokenPayload } from 'src/shared/types/jwt.type'
import { Device } from '@prisma/client'
import { TypeOfVerificationCode, TwoFactorMethodType } from '../constants/auth.constants'
import { PrismaTransactionClient } from 'src/shared/repositories/base.repository'
import { Prisma } from '@prisma/client'
import { I18nContext } from 'nestjs-i18n'

@Injectable()
export class AuthenticationService extends BaseAuthService {
  async register(body: RegisterBodyType & { userAgent?: string; ip?: string }) {
    const auditLogEntry: Omit<Partial<AuditLogData>, 'details'> & { details: Prisma.JsonObject } = {
      action: 'USER_REGISTER_ATTEMPT',
      userEmail: body.email,
      ipAddress: body.ip,
      userAgent: body.userAgent,
      status: AuditLogStatus.FAILURE,
      details: {
        otpTokenProvided: !!body.otpToken,
        nameProvided: !!body.name,
        phoneNumberProvided: !!body.phoneNumber
      }
    }

    try {
      const user = await this.prismaService.$transaction(async (tx: PrismaTransactionClient) => {
        const verificationToken = await this.otpService.validateVerificationToken({
          token: body.otpToken,
          email: body.email,
          type: TypeOfVerificationCode.REGISTER,
          tokenType: 'OTP',
          tx
        })

        if (verificationToken.userId) {
          auditLogEntry.userId = verificationToken.userId
        }
        auditLogEntry.details.verificationTokenDeviceId = verificationToken.deviceId

        if (verificationToken.deviceId && body.userAgent && body.ip) {
          const isValidDevice = await this.deviceService.validateDevice(
            verificationToken.deviceId,
            body.userAgent,
            body.ip,
            tx
          )
          if (!isValidDevice) {
            auditLogEntry.errorMessage = DeviceMismatchException.message
            auditLogEntry.details.reason = 'DEVICE_MISMATCH_ON_REGISTER'
            auditLogEntry.details.validatedDeviceId = verificationToken.deviceId
            throw DeviceMismatchException
          }
          auditLogEntry.details.deviceValidatedOnRegister = true
        }

        const clientRoleId = await this.rolesService.getClientRoleId()
        const hashedPassword = await this.hashingService.hash(body.password)

        const existingUserCheck = await tx.user.findUnique({ where: { email: body.email }, select: { id: true } })
        if (existingUserCheck) {
          auditLogEntry.errorMessage = EmailAlreadyExistsException.message
          auditLogEntry.details.reason = 'EMAIL_ALREADY_EXISTS_PRE_CREATE_CHECK'
        }

        const createdUser = await this.authRepository.createUser(
          {
            email: body.email,
            name: body.name,
            phoneNumber: body.phoneNumber,
            password: hashedPassword,
            roleId: clientRoleId
          },
          tx
        )

        auditLogEntry.userId = createdUser.id
        auditLogEntry.status = AuditLogStatus.SUCCESS
        auditLogEntry.action = 'USER_REGISTER_SUCCESS'
        auditLogEntry.details.roleIdAssigned = clientRoleId

        await this.otpService.deleteOtpToken(body.otpToken, tx)

        return createdUser
      })
      await this.auditLogService.record(auditLogEntry as AuditLogData)
      return user
    } catch (error) {
      if (
        isUniqueConstraintPrismaError(error) ||
        (auditLogEntry.details.reason === 'EMAIL_ALREADY_EXISTS_PRE_CREATE_CHECK' && !auditLogEntry.errorMessage)
      ) {
        auditLogEntry.errorMessage = EmailAlreadyExistsException.message
        auditLogEntry.details.reason = 'EMAIL_ALREADY_EXISTS'
      } else if (!auditLogEntry.errorMessage) {
        auditLogEntry.errorMessage = error instanceof Error ? error.message : 'Unknown error during registration'
        if (error instanceof ApiException) {
          auditLogEntry.errorMessage = JSON.stringify(error.getResponse())
        }
      }
      await this.auditLogService.record(auditLogEntry as AuditLogData)
      if (isUniqueConstraintPrismaError(error)) {
        throw EmailAlreadyExistsException
      }
      throw error
    }
  }

  async login(body: LoginBodyType & { userAgent: string; ip: string }, res?: Response) {
    const auditLogEntry: Omit<Partial<AuditLogData>, 'details'> & { details: Prisma.JsonObject } = {
      action: 'USER_LOGIN_ATTEMPT',
      userEmail: body.email,
      ipAddress: body.ip,
      userAgent: body.userAgent,
      status: AuditLogStatus.FAILURE,
      details: {
        rememberMeRequested: body.rememberMe
      } as Prisma.JsonObject
    }
    try {
      const result = await this.prismaService.$transaction(async (tx: PrismaTransactionClient) => {
        const user = await tx.user.findUnique({
          where: { email: body.email },
          include: { role: true }
        })
        if (!user) {
          auditLogEntry.errorMessage = EmailNotFoundException.message
          auditLogEntry.details.reason = 'USER_NOT_FOUND'
          throw EmailNotFoundException
        }
        auditLogEntry.userId = user.id

        const isPasswordMatch = await this.hashingService.compare(body.password, user.password)
        if (!isPasswordMatch) {
          this.logger.warn('[DEBUG AuthenticationService login] Invalid password for user:', user.email)
          auditLogEntry.errorMessage = InvalidPasswordException.message
          auditLogEntry.details.reason = 'INVALID_PASSWORD'
          throw InvalidPasswordException
        }

        let device: Device
        try {
          device = await this.deviceService.findOrCreateDevice(
            {
              userId: user.id,
              userAgent: body.userAgent,
              ip: body.ip
            },
            tx
          )
          auditLogEntry.details.deviceId = device.id
        } catch (error) {
          this.logger.error('[DEBUG AuthenticationService login] Error creating/finding device:', error)
          auditLogEntry.errorMessage = DeviceSetupFailedException.message
          auditLogEntry.details.deviceError = 'DeviceSetupFailed'
          throw DeviceSetupFailedException
        }

        if (!this.deviceService.isSessionValid(device)) {
          this.logger.warn(
            `[SECURITY AuthenticationService login] Absolute session lifetime exceeded for user ${user.id}, device ${device.id}. Forcing re-login.`
          )
          await this.tokenService.deleteAllRefreshTokensForDevice(device.id, tx)
          auditLogEntry.errorMessage = AbsoluteSessionLifetimeExceededException.message
          auditLogEntry.details.reason = 'ABSOLUTE_SESSION_LIFETIME_EXCEEDED_LOGIN'
          auditLogEntry.notes = `All refresh tokens for device ${device.id} invalidated due to absolute session lifetime exceeded during login.`
          throw AbsoluteSessionLifetimeExceededException
        }

        const shouldAskToTrustDevice = !device.isTrusted

        if (user.twoFactorEnabled && user.twoFactorSecret && user.twoFactorMethod && !device.isTrusted) {
          auditLogEntry.details.twoFactorMethod = user.twoFactorMethod
          const loginSessionToken = await this.otpService.createOtpToken({
            email: user.email,
            type: TypeOfVerificationCode.LOGIN_2FA,
            userId: user.id,
            deviceId: device.id,
            metadata: { rememberMe: body.rememberMe },
            tx
          })
          auditLogEntry.status = AuditLogStatus.SUCCESS
          auditLogEntry.notes = '2FA required: Device not trusted.'
          const message = await this.i18nService.translate('error.Auth.Login.2FARequired', {
            lang: I18nContext.current()?.lang
          })
          return {
            message,
            loginSessionToken: loginSessionToken,
            twoFactorMethod: user.twoFactorMethod
          }
        } else if (!user.twoFactorEnabled && !device.isTrusted) {
          await this.otpService.sendOTP(user.email, TypeOfVerificationCode.LOGIN_UNTRUSTED_DEVICE_OTP)
          const loginSessionToken = await this.otpService.createOtpToken({
            email: user.email,
            type: TypeOfVerificationCode.LOGIN_UNTRUSTED_DEVICE_OTP,
            userId: user.id,
            deviceId: device.id,
            metadata: { rememberMe: body.rememberMe },
            tx
          })
          auditLogEntry.status = AuditLogStatus.SUCCESS
          auditLogEntry.notes = 'Device verification OTP required: Device not trusted and 2FA not enabled.'
          const message = await this.i18nService.translate('error.Auth.Login.DeviceVerificationOtpRequired', {
            lang: I18nContext.current()?.lang
          })
          return {
            message,
            loginSessionToken: loginSessionToken,
            twoFactorMethod: TwoFactorMethodType.OTP
          }
        }

        const { accessToken, refreshToken, maxAgeForRefreshTokenCookie } = await this.tokenService.generateTokens(
          {
            userId: user.id,
            deviceId: device.id,
            roleId: user.roleId,
            roleName: user.role.name
          },
          tx,
          body.rememberMe
        )

        if (res) {
          this.tokenService.setTokenCookies(res, accessToken, refreshToken, maxAgeForRefreshTokenCookie)
        } else {
          this.logger.warn(
            '[DEBUG AuthenticationService login - Direct login] Response object (res) is NOT present. Cookies will not be set by login function directly.'
          )
        }

        auditLogEntry.status = AuditLogStatus.SUCCESS
        auditLogEntry.action = 'USER_LOGIN_SUCCESS'
        return {
          userId: user.id,
          email: user.email,
          name: user.name,
          role: user.role.name,
          askToTrustDevice: shouldAskToTrustDevice
        }
      })
      await this.auditLogService.record(auditLogEntry as AuditLogData)
      return result
    } catch (error) {
      if (!auditLogEntry.errorMessage) {
        auditLogEntry.errorMessage = error instanceof Error ? error.message : 'Unknown error during login'
        if (error instanceof ApiException) {
          auditLogEntry.errorMessage = JSON.stringify(error.getResponse())
        }
      }
      await this.auditLogService.record(auditLogEntry as AuditLogData)
      throw error
    }
  }

  async logout(req: Request, res: Response) {
    const accessToken = this.tokenService.extractTokenFromRequest(req)
    const refreshToken = this.tokenService.extractRefreshTokenFromRequest(req)
    const auditLogEntry: AuditLogData = {
      action: 'USER_LOGOUT',
      status: AuditLogStatus.SUCCESS,
      details: {
        accessTokenProvided: !!accessToken,
        refreshTokenProvided: !!refreshToken
      } as Prisma.JsonObject
    }

    try {
      if (accessToken) {
        const decoded = await this.tokenService.verifyAccessToken(accessToken).catch(() => null)
        if (decoded) {
          auditLogEntry.userId = decoded.userId
          if (auditLogEntry.details && typeof auditLogEntry.details === 'object') {
            ;(auditLogEntry.details as Prisma.JsonObject).deviceId = decoded.deviceId
          }
          if (refreshToken) {
            await this.tokenService.deleteRefreshToken(refreshToken)
          } else {
            auditLogEntry.notes = 'No refresh token provided during logout'
          }
        } else {
          auditLogEntry.notes = 'Invalid access token provided during logout'
        }
      } else {
        auditLogEntry.notes = 'No access token provided during logout'
      }

      this.tokenService.clearTokenCookies(res)
      await this.auditLogService.record(auditLogEntry)
      const message = await this.i18nService.translate('error.Auth.Logout.Success', {
        lang: I18nContext.current()?.lang
      })
      return { message }
    } catch (error) {
      // Even if there's an error, we want to clear cookies
      this.tokenService.clearTokenCookies(res)
      auditLogEntry.errorMessage = error.message
      auditLogEntry.status = AuditLogStatus.FAILURE
      await this.auditLogService.record(auditLogEntry)
      const message = await this.i18nService.translate('error.Auth.Logout.Processed', {
        lang: I18nContext.current()?.lang
      })
      return { message }
    }
  }

  async setRememberMe(
    activeUser: AccessTokenPayload,
    rememberMe: boolean,
    req: Request,
    res: Response,
    ip: string,
    userAgent: string
  ) {
    const auditLogEntry: AuditLogData = {
      action: 'SET_REMEMBER_ME',
      userId: activeUser.userId,
      ipAddress: ip,
      userAgent: userAgent,
      status: AuditLogStatus.FAILURE,
      details: {
        rememberMeValue: rememberMe,
        deviceId: activeUser.deviceId
      } as Prisma.JsonObject
    }

    try {
      const result = await this.prismaService.$transaction(async (tx: PrismaTransactionClient) => {
        // Invalidate current refresh token
        const currentRefreshToken = this.tokenService.extractRefreshTokenFromRequest(req)
        if (currentRefreshToken) {
          await this.tokenService.deleteRefreshToken(currentRefreshToken, tx)
        }

        // Generate new tokens with updated remember me preference
        const { accessToken, refreshToken, maxAgeForRefreshTokenCookie } = await this.tokenService.generateTokens(
          {
            userId: activeUser.userId,
            deviceId: activeUser.deviceId,
            roleId: activeUser.roleId,
            roleName: activeUser.roleName
          },
          tx,
          rememberMe
        )

        this.tokenService.setTokenCookies(res, accessToken, refreshToken, maxAgeForRefreshTokenCookie)

        auditLogEntry.status = AuditLogStatus.SUCCESS
        const message = await this.i18nService.translate('error.Auth.RememberMe.Set', {
          lang: I18nContext.current()?.lang
        })
        return {
          success: true,
          message
        }
      })

      await this.auditLogService.record(auditLogEntry)
      return result
    } catch (error) {
      auditLogEntry.errorMessage = error.message
      await this.auditLogService.record(auditLogEntry)
      throw error
    }
  }
}
