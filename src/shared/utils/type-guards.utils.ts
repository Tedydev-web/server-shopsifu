import { Prisma } from '@prisma/client'
import { ApiException, ErrorDetailMessage } from '../exceptions/api.exception'

/**
 * Kiểm tra xem một lỗi có phải là lỗi ràng buộc độc nhất của Prisma không
 * @param error Lỗi cần kiểm tra
 * @returns Boolean và type predicate
 */
export function isUniqueConstraintPrismaError(error: any): error is Prisma.PrismaClientKnownRequestError {
  return error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2002'
}

/**
 * Kiểm tra xem một lỗi có phải là lỗi không tìm thấy record của Prisma không
 * @param error Lỗi cần kiểm tra
 * @returns Boolean và type predicate
 */
export function isNotFoundPrismaError(error: any): error is Prisma.PrismaClientKnownRequestError {
  return error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2025'
}

/**
 * Kiểm tra xem một lỗi có phải là lỗi ràng buộc khóa ngoại của Prisma không
 * @param error Lỗi cần kiểm tra
 * @returns Boolean và type predicate
 */
export function isForeignKeyConstraintPrismaError(error: any): error is Prisma.PrismaClientKnownRequestError {
  return error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2003'
}

/**
 * Kiểm tra xem một lỗi có phải là lỗi của Prisma không
 * @param error Lỗi cần kiểm tra
 * @returns Boolean và type predicate
 */
export function isPrismaError(error: any): error is Prisma.PrismaClientKnownRequestError {
  return error instanceof Prisma.PrismaClientKnownRequestError
}

/**
 * Kiểm tra xem một lỗi có phải là ApiException
 * @param error Lỗi cần kiểm tra
 * @returns Boolean và type predicate
 */
export function isApiException(error: any): error is ApiException {
  return error instanceof ApiException
}

/**
 * Kiểm tra xem một giá trị có phải là undefined hoặc null không
 * @param value Giá trị cần kiểm tra
 * @returns Boolean
 */
export function isNullOrUndefined(value: any): value is null | undefined {
  return value === null || value === undefined
}

/**
 * Kiểm tra xem một giá trị có phải là object không
 * @param value Giá trị cần kiểm tra
 * @returns Boolean và type predicate
 */
export function isObject(value: any): value is Record<string, any> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

/**
 * Kiểm tra xem một giá trị có phải là một record không rỗng
 * @param value Giá trị cần kiểm tra
 * @returns Boolean và type predicate
 */
export function isNonEmptyObject(value: any): value is Record<string, any> {
  return isObject(value) && Object.keys(value).length > 0
}

/**
 * Kiểm tra xem một mảng có phải là không rỗng
 * @param arr Mảng cần kiểm tra
 * @returns Boolean và type predicate
 */
export function isNonEmptyArray<T>(arr: T[] | any): arr is T[] {
  return Array.isArray(arr) && arr.length > 0
}

/**
 * Kiểm tra xem một chuỗi có phải là chuỗi không rỗng
 * @param value Chuỗi cần kiểm tra
 * @returns Boolean và type predicate
 */
export function isNonEmptyString(value: any): value is string {
  return typeof value === 'string' && value.trim().length > 0
}

/**
 * Loại bỏ các giá trị undefined và null từ một object
 * @param obj Object cần xử lý
 * @returns Object mới không chứa giá trị undefined và null
 */
export function removeNullAndUndefined<T extends Record<string, any>>(obj: T): Partial<T> {
  return Object.entries(obj).reduce((acc, [key, value]) => {
    if (!isNullOrUndefined(value)) {
      acc[key as keyof T] = value
    }
    return acc
  }, {} as Partial<T>)
}

/**
 * Chuyển đổi lỗi thành định dạng chuẩn cho ApiException
 * @param error Lỗi cần chuyển đổi
 * @param defaultCode Mã lỗi mặc định
 * @param defaultMessage Thông điệp lỗi mặc định
 * @returns Thông điệp lỗi chuẩn hoá
 */
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
