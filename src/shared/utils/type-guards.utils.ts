export function isObject(value: unknown): value is object {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

export function isFunction(value: unknown): value is (...args: any[]) => any {
  return typeof value === 'function'
}

export function isString(value: unknown): value is string {
  return typeof value === 'string'
}

export function isNumber(value: unknown): value is number {
  return typeof value === 'number' && !isNaN(value)
}

export function isNullOrUndefined(value: unknown): value is null | undefined {
  return value === null || value === undefined
}

export function isNil(value: unknown): value is null | undefined {
  return isNullOrUndefined(value)
}

export function isNonEmptyString(value: unknown): value is string {
  return isString(value) && value.trim().length > 0
}

export function isNonEmptyArray<T>(value: unknown): value is T[] {
  return Array.isArray(value) && value.length > 0
}

export function isValidEnum<T extends Record<string, string | number>>(value: any, enumObject: T): value is T[keyof T] {
  return Object.values(enumObject).includes(value)
}
