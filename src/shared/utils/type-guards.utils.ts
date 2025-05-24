import { Prisma } from '@prisma/client'
import { ApiException, ErrorDetailMessage } from '../exceptions/api.exception'
import { randomInt } from 'crypto'

export function isUniqueConstraintPrismaError(error: any): error is Prisma.PrismaClientKnownRequestError {
  return error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2002'
}

export function isNotFoundPrismaError(error: any): error is Prisma.PrismaClientKnownRequestError {
  return error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2025'
}

export function isForeignKeyConstraintPrismaError(error: any): error is Prisma.PrismaClientKnownRequestError {
  return error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2003'
}

export function isPrismaError(error: any): error is Prisma.PrismaClientKnownRequestError {
  return error instanceof Prisma.PrismaClientKnownRequestError
}

export function isApiException(error: any): error is ApiException {
  return error instanceof ApiException
}

export function isNullOrUndefined(value: any): value is null | undefined {
  return value === null || value === undefined
}

export function isObject(value: any): value is Record<string, any> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

export function isNonEmptyObject(value: any): value is Record<string, any> {
  return isObject(value) && Object.keys(value).length > 0
}

export function isNonEmptyArray<T>(arr: T[]): arr is T[] {
  return Array.isArray(arr) && arr.length > 0
}

export function isNonEmptyString(value: any): value is string {
  return typeof value === 'string' && value.trim().length > 0
}

export function removeNullAndUndefined<T extends Record<string, any>>(obj: T): Partial<T> {
  return Object.entries(obj).reduce((acc, [key, value]) => {
    if (!isNullOrUndefined(value)) {
      acc[key as keyof T] = value
    }
    return acc
  }, {} as Partial<T>)
}

export function normalizeErrorMessage(
  error: any,
  defaultCode: string = 'Error.Global.InternalServerError',
  defaultMessage: string = 'An unexpected error occurred'
): { message: string; details?: ErrorDetailMessage[] } {
  if (isApiException(error)) {
    return {
      message: error.message || defaultMessage,
      details: error.details
    }
  }

  if (error instanceof Error) {
    return {
      message: error.message || defaultMessage,
      details: [{ code: defaultCode }]
    }
  }

  if (isObject(error) && 'message' in error) {
    return {
      message: String(error.message) || defaultMessage,
      details: [{ code: defaultCode }]
    }
  }

  return {
    message: defaultMessage,
    details: [{ code: defaultCode }]
  }
}

/**
 * Tạo một mã OTP ngẫu nhiên 6 số
 * @returns Chuỗi 6 số từ 100000 đến 999999
 */
export const generateOTP = () => {
  return String(randomInt(100000, 1000000))
}
