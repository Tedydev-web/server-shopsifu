import { z } from 'zod'
import { isNonEmptyArray, isNonEmptyString, isNullOrUndefined, isObject } from './type-guards.utils'
import { ApiException } from '../exceptions/api.exception'

/**
 * Chuyển đổi giá trị thành chuỗi an toàn, loại bỏ undefined và null
 * @param value Giá trị cần chuyển đổi
 * @param defaultValue Giá trị mặc định khi value là null hoặc undefined
 * @returns Chuỗi đã được chuyển đổi
 */
export function safeString(value: any, defaultValue: string = ''): string {
  if (isNullOrUndefined(value)) {
    return defaultValue
  }

  return String(value)
}

/**
 * Chuyển đổi giá trị thành số an toàn
 * @param value Giá trị cần chuyển đổi
 * @param defaultValue Giá trị mặc định khi chuyển đổi thất bại
 * @returns Số đã được chuyển đổi hoặc giá trị mặc định
 */
export function safeNumber(value: any, defaultValue: number = 0): number {
  if (isNullOrUndefined(value)) {
    return defaultValue
  }

  const num = Number(value)
  return isNaN(num) ? defaultValue : num
}

/**
 * Chuyển đổi giá trị thành boolean an toàn
 * @param value Giá trị cần chuyển đổi
 * @param defaultValue Giá trị mặc định khi value là null hoặc undefined
 * @returns Boolean đã được chuyển đổi
 */
export function safeBoolean(value: any, defaultValue: boolean = false): boolean {
  if (isNullOrUndefined(value)) {
    return defaultValue
  }

  if (typeof value === 'boolean') {
    return value
  }

  if (typeof value === 'string') {
    const lowercaseValue = value.toLowerCase().trim()
    return lowercaseValue === 'true' || lowercaseValue === '1' || lowercaseValue === 'yes'
  }

  if (typeof value === 'number') {
    return value !== 0
  }

  return Boolean(value)
}

/**
 * Chuyển đổi an toàn giá trị thành đối tượng Date
 * @param value Giá trị cần chuyển đổi
 * @param defaultValue Giá trị mặc định khi chuyển đổi thất bại
 * @returns Đối tượng Date hoặc null
 */
export function safeDate(value: any, defaultValue: Date | null = null): Date | null {
  if (isNullOrUndefined(value)) {
    return defaultValue
  }

  if (value instanceof Date) {
    return isNaN(value.getTime()) ? defaultValue : value
  }

  const date = new Date(value)
  return isNaN(date.getTime()) ? defaultValue : date
}

/**
 * Chuyển đổi đối tượng thành chuỗi JSON an toàn
 * @param obj Đối tượng cần chuyển đổi
 * @param defaultValue Giá trị mặc định khi chuyển đổi thất bại
 * @returns Chuỗi JSON
 */
export function safeStringify(obj: any, defaultValue: string = '{}'): string {
  try {
    return JSON.stringify(obj)
  } catch (error) {
    return defaultValue
  }
}

/**
 * Phân tích chuỗi JSON thành đối tượng an toàn
 * @param jsonString Chuỗi JSON cần phân tích
 * @param defaultValue Giá trị mặc định khi phân tích thất bại
 * @returns Đối tượng đã được phân tích
 */
export function safeParse<T = any>(jsonString: string, defaultValue: T): T {
  if (!isNonEmptyString(jsonString)) {
    return defaultValue
  }

  try {
    return JSON.parse(jsonString) as T
  } catch (error) {
    return defaultValue
  }
}

/**
 * Trích xuất giá trị an toàn từ đối tượng theo đường dẫn
 * @param obj Đối tượng nguồn
 * @param path Đường dẫn đến giá trị (e.g., 'user.profile.name')
 * @param defaultValue Giá trị mặc định khi không tìm thấy
 * @returns Giá trị được trích xuất hoặc giá trị mặc định
 */
export function getNestedValue<T = any>(obj: any, path: string, defaultValue: T): T {
  if (!isObject(obj) || !isNonEmptyString(path)) {
    return defaultValue
  }

  const properties = path.split('.')
  let value: any = obj

  for (const prop of properties) {
    if (!isObject(value) || !(prop in value)) {
      return defaultValue
    }
    value = value[prop]
  }

  return isNullOrUndefined(value) ? defaultValue : value
}

/**
 * Lọc mảng để loại bỏ các giá trị null hoặc undefined
 * @param array Mảng đầu vào
 * @returns Mảng đã lọc
 */
export function filterNullish<T>(array: (T | null | undefined)[]): T[] {
  return array.filter((item): item is T => !isNullOrUndefined(item))
}

/**
 * Xác thực đối tượng với schema Zod và ném ra ngoại lệ API nếu không hợp lệ
 * @param schema Schema Zod
 * @param data Dữ liệu cần xác thực
 * @param errorMessage Thông báo lỗi tùy chỉnh
 * @returns Dữ liệu đã được xác thực và ép kiểu
 * @throws ApiException nếu xác thực thất bại
 */
export function validateWithZod<T>(schema: z.ZodType<T>, data: unknown, errorMessage?: string): T {
  try {
    return schema.parse(data)
  } catch (error) {
    if (error instanceof z.ZodError) {
      const formattedError = error.format()
      throw new ApiException(
        400,
        'VALIDATION_ERROR',
        errorMessage || 'Invalid input data',
        error.errors.map((err) => ({
          code: 'VALIDATION_ERROR',
          path: err.path.join('.')
        }))
      )
    }
    throw error
  }
}

/**
 * Kiểm tra một giá trị có phải là một đối tượng JSON hợp lệ không
 * @param value Giá trị cần kiểm tra
 * @returns Boolean
 */
export function isValidJson(value: any): boolean {
  if (!isNonEmptyString(value)) {
    return false
  }

  try {
    const result = JSON.parse(value)
    return isObject(result) || Array.isArray(result)
  } catch (error) {
    return false
  }
}

/**
 * Chuẩn hóa chuỗi (loại bỏ dấu, khoảng trắng thừa, v.v.)
 * @param text Chuỗi cần chuẩn hóa
 * @returns Chuỗi đã được chuẩn hóa
 */
export function normalizeString(text: string): string {
  if (!isNonEmptyString(text)) {
    return ''
  }

  return text
    .trim()
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/\s+/g, ' ')
}

/**
 * Trích xuất đối tượng với chỉ các thuộc tính được chỉ định
 * @param obj Đối tượng nguồn
 * @param keys Danh sách khóa cần giữ lại
 * @returns Đối tượng mới chỉ với các thuộc tính được chỉ định
 */
export function pick<T extends Record<string, any>, K extends keyof T>(obj: T, keys: K[]): Pick<T, K> {
  if (!isObject(obj) || !isNonEmptyArray(keys)) {
    return {} as Pick<T, K>
  }

  return keys.reduce(
    (result, key) => {
      if (key in obj) {
        result[key] = obj[key]
      }
      return result
    },
    {} as Pick<T, K>
  )
}

/**
 * Trích xuất đối tượng loại bỏ các thuộc tính được chỉ định
 * @param obj Đối tượng nguồn
 * @param keys Danh sách khóa cần loại bỏ
 * @returns Đối tượng mới không có các thuộc tính bị loại bỏ
 */
export function omit<T extends Record<string, any>, K extends keyof T>(obj: T, keys: K[]): Omit<T, K> {
  if (!isObject(obj)) {
    return {} as Omit<T, K>
  }

  if (!isNonEmptyArray(keys)) {
    return { ...obj }
  }

  const result = { ...obj }
  for (const key of keys) {
    delete result[key]
  }

  return result
}

/**
 * Trả về một phần tử ngẫu nhiên từ mảng
 * @param array Mảng đầu vào
 * @returns Phần tử ngẫu nhiên hoặc undefined nếu mảng rỗng
 */
export function getRandomElement<T>(array: T[]): T | undefined {
  if (!isNonEmptyArray(array)) {
    return undefined
  }

  const randomIndex = Math.floor(Math.random() * array.length)
  return array[randomIndex]
}

/**
 * Xác thực chuỗi email
 * @param email Chuỗi email cần xác thực
 * @returns Boolean
 */
export function isValidEmail(email: string): boolean {
  if (!isNonEmptyString(email)) {
    return false
  }

  // RFC 5322 Official Standard
  const emailRegex =
    /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/
  return emailRegex.test(email)
}

/**
 * Xác thực số điện thoại (định dạng quốc tế)
 * @param phone Chuỗi số điện thoại cần xác thực
 * @returns Boolean
 */
export function isValidPhone(phone: string): boolean {
  if (!isNonEmptyString(phone)) {
    return false
  }

  // Định dạng E.164 (tiêu chuẩn quốc tế)
  const phoneRegex = /^\+?[1-9]\d{1,14}$/
  return phoneRegex.test(phone.replace(/\s+/g, ''))
}

/**
 * Kiểm tra xem một giá trị có phải là giá trị enum hợp lệ không
 * @param value Giá trị cần kiểm tra
 * @param enumObject Đối tượng enum
 * @returns Boolean
 */
export function isValidEnum<T extends Record<string, string | number>>(value: any, enumObject: T): value is T[keyof T] {
  if (isNullOrUndefined(value)) {
    return false
  }

  return Object.values(enumObject).includes(value)
}
