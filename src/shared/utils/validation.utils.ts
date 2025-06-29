import { z } from 'zod'

export function safeString(value: any, defaultValue: string = ''): string {
  if (typeof value === 'string') {
    return value
  }
  if (typeof value === 'number') {
    return String(value)
  }
  return defaultValue
}

export function safeNumber(value: any, defaultValue: number = 0): number {
  if (typeof value === 'number' && !isNaN(value)) {
    return value
  }
  if (typeof value === 'string') {
    const parsed = Number(value)
    return isNaN(parsed) ? defaultValue : parsed
  }
  return defaultValue
}

export function safeBoolean(value: any, defaultValue: boolean = false): boolean {
  if (typeof value === 'boolean') {
    return value
  }
  if (typeof value === 'string') {
    const lower = value.toLowerCase()
    if (lower === 'true' || lower === '1' || lower === 'yes') {
      return true
    }
    if (lower === 'false' || lower === '0' || lower === 'no') {
      return false
    }
  }
  if (typeof value === 'number') {
    return value !== 0
  }
  return defaultValue
}

export function safeDate(value: any, defaultValue: Date | null = null): Date | null {
  if (value instanceof Date && !isNaN(value.getTime())) {
    return value
  }
  if (typeof value === 'string' || typeof value === 'number') {
    const date = new Date(value)
    if (!isNaN(date.getTime())) {
      return date
    }
  }
  return defaultValue
}

export function safeStringify(obj: any, defaultValue: string = '{}'): string {
  try {
    return JSON.stringify(obj)
  } catch {
    return defaultValue
  }
}

export function safeParse<T = any>(jsonString: string, defaultValue: T): T {
  try {
    return JSON.parse(jsonString)
  } catch {
    return defaultValue
  }
}

export function getNestedValue<T = any>(obj: any, path: string, defaultValue: T): T {
  if (!obj || typeof obj !== 'object') {
    return defaultValue
  }

  const keys = path.split('.')
  let current = obj

  for (const key of keys) {
    if (current == null || typeof current !== 'object' || !(key in current)) {
      return defaultValue
    }
    current = current[key]
  }

  return current !== undefined ? current : defaultValue
}

export function filterNullish<T>(array: (T | null | undefined)[]): T[] {
  return array.filter((item): item is T => item != null)
}

export function validateWithZod<T>(schema: z.ZodType<T>, data: unknown, errorMessage?: string): T {
  try {
    return schema.parse(data)
  } catch (error) {
    if (error instanceof z.ZodError) {
      const firstError = error.errors[0]
      const message = errorMessage || `Validation failed: ${firstError.message} at ${firstError.path.join('.')}`
      throw new Error(message)
    }
    throw error
  }
}

export function isValidJson(value: any): boolean {
  if (typeof value !== 'string') {
    return false
  }
  try {
    JSON.parse(value)
    return true
  } catch {
    return false
  }
}

export function normalizeString(text: string): string {
  return text
    .trim()
    .toLowerCase()
    .replace(/\s+/g, ' ')
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
}

export function pick<T extends Record<string, any>, K extends keyof T>(obj: T, keys: K[]): Pick<T, K> {
  const result = {} as Pick<T, K>
  for (const key of keys) {
    if (key in obj) {
      result[key] = obj[key]
    }
  }
  return result
}

export function omit<T extends Record<string, any>, K extends keyof T>(obj: T, keys: K[]): Omit<T, K> {
  const result = { ...obj } as any
  for (const key of keys) {
    delete result[key]
  }
  return result
}

export function getRandomElement<T>(array: T[]): T | undefined {
  if (array.length === 0) {
    return undefined
  }
  const randomIndex = Math.floor(Math.random() * array.length)
  return array[randomIndex]
}

export function safeJsonParse<T>(jsonString: string | null | undefined): T | null {
  if (!jsonString) return null
  try {
    return JSON.parse(jsonString) as T
  } catch {
    return null
  }
}
