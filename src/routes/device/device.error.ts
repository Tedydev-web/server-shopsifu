import {
  NotFoundError,
  ForbiddenError,
  ConflictError,
  BadRequestError,
  UnauthorizedError,
  InternalServerError,
} from 'src/shared/error'

export const DeviceError = {
  // === Device Not Found Errors ===
  DeviceNotFound: NotFoundError('device.error.DEVICE_NOT_FOUND'),
  DeviceNotBelongToUser: ForbiddenError('device.error.DEVICE_NOT_BELONG_TO_USER'),

  // === Device Trust Errors ===
  DeviceNotTrusted: ForbiddenError('device.error.DEVICE_NOT_TRUSTED'),
  DeviceTrustExpired: ForbiddenError('device.error.DEVICE_TRUST_EXPIRED'),
  DeviceAlreadyTrusted: ConflictError('device.error.DEVICE_ALREADY_TRUSTED'),

  // === Device Activity Errors ===
  DeviceInactive: ForbiddenError('device.error.DEVICE_INACTIVE'),
  DeviceRevoked: ForbiddenError('device.error.DEVICE_REVOKED'),

  // === Device Management Errors ===
  DeviceLimitExceeded: BadRequestError('device.error.DEVICE_LIMIT_EXCEEDED'),
  DeviceNameRequired: BadRequestError('device.error.DEVICE_NAME_REQUIRED'),
  DeviceNameTooLong: BadRequestError('device.error.DEVICE_NAME_TOO_LONG'),
  DeviceNameInvalid: BadRequestError('device.error.DEVICE_NAME_INVALID'),

  // === Device Fingerprint Errors ===
  InvalidDeviceFingerprint: BadRequestError('device.error.INVALID_DEVICE_FINGERPRINT'),
  DeviceFingerprintRequired: BadRequestError('device.error.DEVICE_FINGERPRINT_REQUIRED'),

  // === Device Session Errors ===
  DeviceSessionNotFound: NotFoundError('device.error.DEVICE_SESSION_NOT_FOUND'),
  DeviceSessionExpired: UnauthorizedError('device.error.DEVICE_SESSION_EXPIRED'),
  DeviceSessionRevoked: UnauthorizedError('device.error.DEVICE_SESSION_REVOKED'),

  // === System Errors ===
  DeviceCreationFailed: InternalServerError('device.error.DEVICE_CREATION_FAILED'),
  DeviceUpdateFailed: InternalServerError('device.error.DEVICE_UPDATE_FAILED'),
  DeviceDeletionFailed: InternalServerError('device.error.DEVICE_DELETION_FAILED'),
  DeviceRevokeFailed: InternalServerError('device.error.DEVICE_REVOKE_FAILED'),
} as const

export type DeviceErrorKey = keyof typeof DeviceError
