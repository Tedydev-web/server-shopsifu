import { z } from 'zod'
import { isNonEmptyArray, isNonEmptyString, isNullOrUndefined, isObject } from './type-guards.utils'
import { ApiException } from '../exceptions/api.exception'

export function safeString(value: any, defaultValue: string = ''): string {
  if (isNullOrUndefined(value)) {
    return defaultValue
  }

  return String(value)
}

export function safeNumber(value: any, defaultValue: number = 0): number {
  if (isNullOrUndefined(value)) {
    return defaultValue
  }

  const num = Number(value)
  return isNaN(num) ? defaultValue : num
}

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

export function safeStringify(obj: any, defaultValue: string = '{}'): string {
  try {
    return JSON.stringify(obj)
  } catch {
    return defaultValue
  }
}

export function safeParse<T = any>(jsonString: string, defaultValue: T): T {
  if (!isNonEmptyString(jsonString)) {
    return defaultValue
  }

  try {
    return JSON.parse(jsonString) as T
  } catch {
    return defaultValue
  }
}

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

export function filterNullish<T>(array: (T | null | undefined)[]): T[] {
  return array.filter((item): item is T => !isNullOrUndefined(item))
}

export function validateWithZod<T>(schema: z.ZodType<T>, data: unknown, errorMessage?: string): T {
  try {
    return schema.parse(data)
  } catch (error) {
    if (error instanceof z.ZodError) {
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

export function isValidJson(value: any): boolean {
  if (!isNonEmptyString(value)) {
    return false
  }

  try {
    const result = JSON.parse(value)
    return isObject(result) || Array.isArray(result)
  } catch {
    return false
  }
}

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

export function getRandomElement<T>(array: T[]): T | undefined {
  if (!isNonEmptyArray(array)) {
    return undefined
  }

  const randomIndex = Math.floor(Math.random() * array.length)
  return array[randomIndex]
}

export function isValidEnum<T extends Record<string, string | number>>(value: any, enumObject: T): value is T[keyof T] {
  if (isNullOrUndefined(value)) {
    return false
  }

  return Object.values(enumObject).includes(value)
}
