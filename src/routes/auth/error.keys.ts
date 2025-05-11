/**
 * Định nghĩa các khóa lỗi để hỗ trợ đa ngôn ngữ.
 * Frontend sẽ sử dụng các khóa này để hiển thị thông báo lỗi theo ngôn ngữ hiện tại.
 */

export enum PasswordErrorKeys {
  MIN_LENGTH = 'error.password.minLength',
  MAX_LENGTH = 'error.password.maxLength',
  UPPERCASE = 'error.password.uppercase',
  LOWERCASE = 'error.password.lowercase',
  NUMBER = 'error.password.number',
  SPECIAL_CHAR = 'error.password.specialChar',
  MATCH = 'error.password.match',
  INVALID = 'error.password.invalid'
}

export enum EmailErrorKeys {
  INVALID = 'error.email.invalid',
  EXISTS = 'error.email.exists',
  NOT_FOUND = 'error.email.notFound'
}

export enum OtpErrorKeys {
  INVALID = 'error.otp.invalid',
  EXPIRED = 'error.otp.expired',
  TOO_MANY_ATTEMPTS = 'error.otp.tooManyAttempts',
  FAILED_TO_SEND = 'error.otp.failedToSend'
}

export enum TokenErrorKeys {
  EXPIRED = 'error.token.expired',
  INVALID = 'error.token.invalid',
  ALREADY_USED = 'error.token.alreadyUsed',
  INVALID_TYPE = 'error.token.invalidType',
  UNAUTHORIZED = 'error.token.unauthorized'
}

export enum GoogleErrorKeys {
  FAILED_TO_GET_INFO = 'error.google.failedToGetInfo'
}

export enum TwoFactorErrorKeys {
  ONE_REQUIRED = 'error.auth.twoFactor.oneRequired',
  SETUP_FAILED = 'error.auth.twoFactor.setupFailed',
  VERIFY_FAILED = 'error.auth.twoFactor.verifyFailed',
  ALREADY_ENABLED = 'error.auth.twoFactor.alreadyEnabled',
  NOT_ENABLED = 'error.auth.twoFactor.notEnabled'
}

export enum RequestErrorKeys {
  RATE_LIMIT_EXCEEDED = 'error.request.rateLimitExceeded',
  VALIDATION_FAILED = 'error.request.validationFailed',
  BAD_REQUEST = 'error.request.badRequest',
  INTERNAL_SERVER_ERROR = 'error.server.internal',
  DATABASE_ERROR = 'error.database.general',
  UNIQUE_CONSTRAINT = 'error.database.uniqueConstraint'
}
 