import { NotFoundException, UnprocessableEntityException } from '@nestjs/common'
import { ForbiddenException, UnauthorizedException } from '@nestjs/common'

export const NotFoundRecordException = new NotFoundException('global.error.NOT_FOUND_RECORD')

export const UnauthorizedError = new UnauthorizedException('global.error.UNAUTHORIZED')
export const ForbiddenError = new ForbiddenException('global.error.FORBIDDEN')

export const InvalidPasswordException = new UnprocessableEntityException([
  {
    message: 'global.error.INVALID_PASSWORD',
    path: 'password',
  },
])
