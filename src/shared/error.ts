import {
  NotFoundException,
  UnprocessableEntityException,
  UnauthorizedException as NestUnauthorizedException,
  ForbiddenException as NestForbiddenException,
  ConflictException
} from '@nestjs/common'

export const NotFoundRecordException = new NotFoundException('global.global.error.NOT_FOUND_RECORD')

export const InvalidPasswordException = new UnprocessableEntityException([
  {
    message: 'global.global.error.INVALID_PASSWORD',
    path: 'password'
  }
])

export const UnauthorizedException = new NestUnauthorizedException('global.global.error.UNAUTHORIZED')

export const ForbiddenException = new NestForbiddenException('global.global.error.FORBIDDEN')

export const UserNotActiveException = new UnprocessableEntityException([
  {
    message: 'global.global.error.USER_NOT_ACTIVE',
    path: 'user'
  }
])

export const InsufficientPermissionsException = new NestForbiddenException(
  'global.global.error.INSUFFICIENT_PERMISSIONS'
)

export const SessionNotFoundException = new NotFoundException('global.global.error.SESSION_NOT_FOUND')

export const TokenBlacklistedException = new NestUnauthorizedException('global.global.error.TOKEN_BLACKLISTED')

export const VersionConflictException = new ConflictException('Error.VersionConflict')
