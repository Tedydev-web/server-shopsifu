import { Injectable, Logger, HttpStatus } from '@nestjs/common'
import { OAuth2Client } from 'google-auth-library'
import { google } from 'googleapis'
import { GoogleAuthStateType } from 'src/routes/auth/auth.model'
import { RolesService } from 'src/routes/auth/roles.service'
import envConfig from 'src/shared/config'
import { HashingService } from 'src/shared/services/hashing.service'
import { v4 as uuidv4 } from 'uuid'
import { DeviceService } from 'src/routes/auth/providers/device.service'
import { OtpService } from 'src/routes/auth/providers/otp.service'
import { PrismaService } from 'src/shared/services/prisma.service'
import { I18nService, I18nContext } from 'nestjs-i18n'
import { RedisService } from 'src/shared/providers/redis/redis.service'
import {
  Prisma,
  Role,
  User,
  Device,
  UserProfile,
  TwoFactorMethodType as PrismaTwoFactorMethodType
} from '@prisma/client'
import { ApiException } from 'src/shared/exceptions/api.exception'
import { TokenPayload } from 'google-auth-library'
import { GetTokenResponse } from 'google-auth-library/build/src/auth/oauth2client'

export interface GoogleCallbackSuccessResult {
  user: User & { role: Role; userProfile: UserProfile | null }
  device: Device
  requiresTwoFactorAuth: boolean
  requiresUntrustedDeviceVerification: boolean
  twoFactorMethod?: PrismaTwoFactorMethodType | null
  isLoginViaGoogle: true
  message: string
}

export interface GoogleCallbackErrorResult {
  errorCode: string
  errorMessage: string
  redirectToError: true
}

export interface GoogleCallbackAccountExistsWithoutLinkResult {
  needsLinking: true
  existingUserId: number
  existingUserEmail: string
  googleId: string
  googleEmail: string
  googleName?: string | null
  googleAvatar?: string | null
  message: string
}

export type GoogleCallbackReturnType =
  | GoogleCallbackSuccessResult
  | GoogleCallbackErrorResult
  | GoogleCallbackAccountExistsWithoutLinkResult

@Injectable()
export class GoogleService {
  private readonly logger = new Logger(GoogleService.name)
  private oauth2Client: OAuth2Client
  constructor(
    private readonly hashingService: HashingService,
    private readonly rolesService: RolesService,
    private readonly deviceService: DeviceService,
    private readonly otpService: OtpService,
    private readonly prismaService: PrismaService,
    private readonly i18nService: I18nService,
    private readonly redisService: RedisService
  ) {
    this.oauth2Client = new google.auth.OAuth2(
      envConfig.GOOGLE_CLIENT_ID,
      envConfig.GOOGLE_CLIENT_SECRET,
      envConfig.GOOGLE_CLIENT_REDIRECT_URI
    )
  }

  async getGoogleTokens(code: string): Promise<GetTokenResponse['tokens']> {
    try {
      const { tokens } = await this.oauth2Client.getToken(code)
      if (!tokens || !tokens.id_token) {
        throw new ApiException(
          HttpStatus.INTERNAL_SERVER_ERROR,
          'GOOGLE_TOKEN_FETCH_FAILED',
          'Error.Auth.Google.TokenFetchFailedOrMissingIdToken'
        )
      }
      return tokens
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Error.Auth.Google.TokenFetchFailed'
      const errorCode = error instanceof ApiException ? error.errorCode : 'GOOGLE_TOKEN_FETCH_ERROR'
      throw new ApiException(HttpStatus.INTERNAL_SERVER_ERROR, errorCode, errorMessage)
    }
  }

  async verifyGoogleIdToken(idToken: string): Promise<TokenPayload | undefined> {
    if (!idToken) {
      return undefined
    }
    try {
      const ticket = await this.oauth2Client.verifyIdToken({
        idToken: idToken,
        audience: envConfig.GOOGLE_CLIENT_ID
      })
      return ticket.getPayload()
    } catch (error) {
      return undefined
    }
  }

  getAuthorizationUrl(stateParams: GoogleAuthStateType): { url: string; nonce: string } {
    const scope = ['https://www.googleapis.com/auth/userinfo.profile', 'https://www.googleapis.com/auth/userinfo.email']

    const nonce = uuidv4()

    const stateObject: GoogleAuthStateType & { nonce: string } = {
      ...stateParams,
      nonce
    }

    const stateString = Buffer.from(JSON.stringify(stateObject)).toString('base64')
    const url = this.oauth2Client.generateAuthUrl({
      access_type: 'offline',
      scope,
      include_granted_scopes: true,
      state: stateString,
      prompt: 'select_account'
    })
    return { url, nonce }
  }
  async googleCallback({
    code,
    state,
    userAgent = 'Unknown',
    ip = 'Unknown'
  }: {
    code: string
    state: string
    userAgent?: string
    ip?: string
  }): Promise<GoogleCallbackReturnType> {
    const currentLang = I18nContext.current()?.lang
    try {
      try {
        if (state) {
          const clientInfo = JSON.parse(Buffer.from(state, 'base64').toString()) as Omit<
            GoogleAuthStateType,
            'rememberMe'
          >
          userAgent = clientInfo.userAgent || userAgent
          ip = clientInfo.ip || ip
        }
      } catch (parseError) {
        console.error('Error parsing state', parseError)
      }
      const tokens = await this.getGoogleTokens(code)
      const payload = await this.verifyGoogleIdToken(tokens.id_token as string)

      if (!payload || !payload.email || !payload.sub) {
        return {
          errorCode: 'INVALID_PAYLOAD',
          errorMessage: await this.i18nService.translate('Error.Auth.Google.InvalidPayload'),
          redirectToError: true
        }
      }

      const googleUserId = payload.sub

      let stateFromServer: { userAgent?: string; ip?: string; nonce: string } | null = null
      try {
        if (state) {
          const parsedState = JSON.parse(Buffer.from(state, 'base64').toString('utf-8'))
          if (
            parsedState &&
            typeof parsedState === 'object' &&
            parsedState !== null &&
            'nonce' in parsedState &&
            typeof parsedState.nonce === 'string'
          ) {
            stateFromServer = {
              nonce: parsedState.nonce,
              userAgent: typeof parsedState.userAgent === 'string' ? parsedState.userAgent : undefined,
              ip: typeof parsedState.ip === 'string' ? parsedState.ip : undefined
            }
            userAgent = stateFromServer?.userAgent || userAgent
            ip = stateFromServer?.ip || ip
          }
        }
      } catch (parseError) {
        this.logger.error('[GoogleCallback] Error parsing state', parseError)
      }

      let user = await this.prismaService.user.findUnique({
        where: { googleId: googleUserId },
        include: { role: true, userProfile: true }
      })

      const clientRoleId = await this.rolesService.getClientRoleId()

      if (user && user.status !== 'ACTIVE') {
        return {
          errorCode: 'USER_NOT_ACTIVE',
          errorMessage: await this.i18nService.translate('Error.Auth.User.NotActive', { lang: currentLang }),
          redirectToError: true
        }
      }

      if (!user) {
        const userByEmail = await this.prismaService.user.findUnique({
          where: { email: payload.email },
          include: { role: true, userProfile: true }
        })

        if (userByEmail) {
          if (userByEmail.googleId && userByEmail.googleId !== googleUserId) {
            return {
              errorCode: 'ACCOUNT_CONFLICT',
              errorMessage: await this.i18nService.translate('Error.Auth.Google.AccountConflict'),
              redirectToError: true
            }
          }

          if (!userByEmail.googleId) {
            if (userByEmail.status !== 'ACTIVE') {
              return {
                errorCode: 'USER_NOT_ACTIVE_FOR_LINKING',
                errorMessage: await this.i18nService.translate('Error.Auth.User.NotActiveForLinking', {
                  lang: currentLang
                }),
                redirectToError: true
              }
            }
            return {
              needsLinking: true,
              existingUserId: userByEmail.id,
              existingUserEmail: userByEmail.email,
              googleId: googleUserId,
              googleEmail: payload.email,
              googleName: payload.name,
              googleAvatar: payload.picture,
              message: await this.i18nService.translate('Auth.Google.PromptLinkAccount', {
                lang: currentLang,
                args: { email: userByEmail.email }
              })
            }
          }

          const userProfileUpdateData: any = {}
          if (
            payload.picture &&
            (!userByEmail.userProfile?.avatar || userByEmail.userProfile.avatar !== payload.picture)
          ) {
            userProfileUpdateData.avatar = payload.picture
          }
          if (
            payload.name &&
            (!userByEmail.userProfile?.firstName || userByEmail.userProfile.firstName !== payload.name)
          ) {
            // Assuming payload.name maps to firstName. Adjust if it's a full name that needs parsing.
            userProfileUpdateData.firstName = payload.name
          }

          user = await this.prismaService.user.update({
            where: { id: userByEmail.id },
            data: {
              googleId: googleUserId,
              ...(!userByEmail.roleId || !userByEmail.role ? { role: { connect: { id: clientRoleId } } } : {}),
              userProfile:
                Object.keys(userProfileUpdateData).length > 0
                  ? {
                      upsert: {
                        create: userProfileUpdateData,
                        update: userProfileUpdateData
                      }
                    }
                  : undefined
            },
            include: { role: true, userProfile: true }
          })
        } else {
          user = await this.prismaService.user.create({
            data: {
              email: payload.email,
              password: await this.hashingService.hash(uuidv4()),
              status: 'ACTIVE',
              role: { connect: { id: clientRoleId } },
              googleId: googleUserId,
              userProfile: {
                // Create UserProfile simultaneously
                create: {
                  firstName: payload.name || undefined, // Store Google's name as firstName
                  avatar: payload.picture || undefined
                }
              }
            },
            include: { role: true, userProfile: true }
          })
        }
      } else {
        const updates: Prisma.UserUpdateInput = {}
        const profileUpdates: Prisma.UserProfileUpdateInput = {}

        // Update UserProfile fields
        if (payload.name && user.userProfile?.firstName !== payload.name) {
          profileUpdates.firstName = payload.name
        }
        if (payload.picture && user.userProfile?.avatar !== payload.picture) {
          profileUpdates.avatar = payload.picture
        }

        if (!user.roleId || !user.role) {
          updates.role = { connect: { id: clientRoleId } }
        }

        const userProfileExists = !!user.userProfile

        if (Object.keys(profileUpdates).length > 0) {
          if (userProfileExists) {
            updates.userProfile = { update: profileUpdates }
          } else {
            updates.userProfile = { create: profileUpdates as Prisma.UserProfileCreateInput }
          }
        }

        if (Object.keys(updates).length > 0) {
          user = await this.prismaService.user.update({
            where: { id: user.id },
            data: updates,
            include: { role: true, userProfile: true }
          })
        }
      }

      if (!user.role) {
        user = await this.prismaService.user.update({
          where: { id: user.id },
          data: { role: { connect: { id: clientRoleId } } },
          include: { role: true, userProfile: true }
        })
      }

      const device = await this.deviceService.findOrCreateDevice({
        userId: user.id,
        userAgent: userAgent,
        ip: ip
      })

      const requiresTwoFactorAuth = !!(
        user.twoFactorEnabled &&
        user.twoFactorSecret &&
        user.twoFactorMethod &&
        !device.isTrusted
      )
      const requiresUntrustedDeviceVerification = !user.twoFactorEnabled && !device.isTrusted

      return {
        user,
        device,
        requiresTwoFactorAuth,
        requiresUntrustedDeviceVerification,
        twoFactorMethod: user.twoFactorMethod,
        isLoginViaGoogle: true,
        message: await this.i18nService.translate('Auth.Google.SuccessProceedToSecurityChecks', { lang: currentLang })
      }
    } catch (error) {
      const resolveErrorCode = (): string => {
        if (error instanceof ApiException) {
          return error.getStatus().toString()
        }
        if (
          typeof error === 'object' &&
          error !== null &&
          'code' in error &&
          typeof (error as { code?: unknown }).code === 'string'
        ) {
          return (error as { code: string }).code
        }
        return 'AUTH_ERROR_GOOGLE_CALLBACK'
      }
      const errorCode = resolveErrorCode()

      let errorMessageKey = 'Error.Auth.Google.CallbackErrorGeneric'
      if (error instanceof ApiException) {
        const errorResponse = error.getResponse()
        if (typeof errorResponse === 'string') {
          errorMessageKey = errorResponse
        } else if (typeof errorResponse === 'object' && errorResponse !== null && 'messageKey' in errorResponse) {
          const potentialMessageKey = (errorResponse as { messageKey?: any }).messageKey
          if (typeof potentialMessageKey === 'string') {
            errorMessageKey = potentialMessageKey
          }
        }
      }

      const translatedMessageFromService: unknown = await this.i18nService.translate(errorMessageKey, {
        lang: currentLang
      })

      let finalErrorMessage: string
      if (typeof translatedMessageFromService === 'string') {
        finalErrorMessage = translatedMessageFromService
      } else {
        finalErrorMessage = await this.i18nService.translate('Error.Auth.Google.CallbackErrorGeneric', {
          lang: currentLang
        })
      }

      return {
        errorCode,
        errorMessage: finalErrorMessage,
        redirectToError: true
      }
    }
  }

  async linkGoogleAccount(
    loggedInUserId: number,
    googleIdToLink: string,
    googleEmail: string,
    googleName: string | null | undefined,
    googleAvatar: string | null | undefined
  ): Promise<User & { role: Role; userProfile: UserProfile | null }> {
    const userToLink = await this.prismaService.user.findUnique({
      where: { id: loggedInUserId },
      include: { role: true, userProfile: true }
    })

    if (!userToLink) {
      throw new ApiException(HttpStatus.NOT_FOUND, 'USER_NOT_FOUND_FOR_LINKING', 'Error.User.NotFound')
    }

    if (userToLink.status !== 'ACTIVE') {
      throw new ApiException(HttpStatus.FORBIDDEN, 'USER_NOT_ACTIVE_FOR_LINKING', 'Error.Auth.User.NotActiveForLinking')
    }

    if (userToLink.googleId && userToLink.googleId !== googleIdToLink) {
      throw new ApiException(
        HttpStatus.CONFLICT,
        'GOOGLE_ALREADY_LINKED_OTHER',
        'Error.Auth.Google.AlreadyLinkedToOtherGoogle'
      )
    }
    if (userToLink.googleId === googleIdToLink) {
      return userToLink
    }

    const userWithThisGoogleId = await this.prismaService.user.findUnique({
      where: { googleId: googleIdToLink }
    })

    if (userWithThisGoogleId && userWithThisGoogleId.id !== loggedInUserId) {
      throw new ApiException(HttpStatus.CONFLICT, 'GOOGLE_ID_CONFLICT', 'Error.Auth.Google.GoogleIdConflict')
    }

    const updateData: Prisma.UserUpdateInput = {
      googleId: googleIdToLink
    }

    const profileUpdates: Prisma.UserProfileUpdateInput = {}
    if (googleName && userToLink.userProfile?.firstName !== googleName) {
      profileUpdates.firstName = googleName
    }
    if (googleAvatar && userToLink.userProfile?.avatar !== googleAvatar) {
      profileUpdates.avatar = googleAvatar
    }

    if (Object.keys(profileUpdates).length > 0) {
      if (userToLink.userProfile) {
        updateData.userProfile = { update: profileUpdates }
      } else {
        updateData.userProfile = { create: profileUpdates as Prisma.UserProfileCreateInput }
      }
    }

    const updatedUser = await this.prismaService.user.update({
      where: { id: loggedInUserId },
      data: updateData,
      include: { role: true, userProfile: true }
    })

    return updatedUser
  }
}
