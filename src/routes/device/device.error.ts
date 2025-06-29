import { GlobalError } from 'src/shared/global.error'

export const DeviceError = {
  // === Device Not Found Errors ===
  DeviceNotFound: GlobalError.NotFound('device.error.DEVICE_NOT_FOUND'),
  DeviceNotBelongToUser: GlobalError.Forbidden('device.error.DEVICE_NOT_BELONG_TO_USER'),

  // === Device Trust Errors ===
  DeviceNotTrusted: GlobalError.Forbidden('device.error.DEVICE_NOT_TRUSTED'),
  DeviceTrustExpired: GlobalError.Forbidden('device.error.DEVICE_TRUST_EXPIRED'),
  DeviceAlreadyTrusted: GlobalError.Conflict('device.error.DEVICE_ALREADY_TRUSTED'),

  // === Device Activity Errors ===
  DeviceInactive: GlobalError.Forbidden('device.error.DEVICE_INACTIVE'),
  DeviceRevoked: GlobalError.Forbidden('device.error.DEVICE_REVOKED'),

  // === Device Management Errors ===
  DeviceLimitExceeded: GlobalError.BadRequest('device.error.DEVICE_LIMIT_EXCEEDED'),
  DeviceNameRequired: GlobalError.BadRequest('device.error.DEVICE_NAME_REQUIRED'),
  DeviceNameTooLong: GlobalError.BadRequest('device.error.DEVICE_NAME_TOO_LONG'),
  DeviceNameInvalid: GlobalError.BadRequest('device.error.DEVICE_NAME_INVALID'),

  // === Device Fingerprint Errors ===
  InvalidDeviceFingerprint: GlobalError.BadRequest('device.error.INVALID_DEVICE_FINGERPRINT'),
  DeviceFingerprintRequired: GlobalError.BadRequest('device.error.DEVICE_FINGERPRINT_REQUIRED'),

  // === Device Session Errors ===
  DeviceSessionNotFound: GlobalError.NotFound('device.error.DEVICE_SESSION_NOT_FOUND'),
  DeviceSessionExpired: GlobalError.Unauthorized('device.error.DEVICE_SESSION_EXPIRED'),
  DeviceSessionRevoked: GlobalError.Unauthorized('device.error.DEVICE_SESSION_REVOKED'),

  // === System Errors ===
  DeviceCreationFailed: GlobalError.InternalServerError('device.error.DEVICE_CREATION_FAILED'),
  DeviceUpdateFailed: GlobalError.InternalServerError('device.error.DEVICE_UPDATE_FAILED'),
  DeviceDeletionFailed: GlobalError.InternalServerError('device.error.DEVICE_DELETION_FAILED'),
  DeviceRevokeFailed: GlobalError.InternalServerError('device.error.DEVICE_REVOKE_FAILED'),
} as const

export type DeviceErrorKey = keyof typeof DeviceError
