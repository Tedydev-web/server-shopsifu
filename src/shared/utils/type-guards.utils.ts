/* eslint-disable @typescript-eslint/ban-types */

export function isObject(value: unknown): value is object {
  return typeof value === 'object' && value !== null
}

export function isFunction(value: unknown): value is Function {
  return typeof value === 'function'
}

export function isString(value: unknown): value is string {
  return typeof value === 'string'
}

export function isNumber(value: unknown): value is number {
  return typeof value === 'number'
}

export function isNullOrUndefined(value: unknown): value is null | undefined {
  return value === null || value === undefined
}

export function isNil(value: unknown): value is null | undefined {
  return isNullOrUndefined(value)
}

export function isNonEmptyString(value: unknown): value is string {
  return isString(value) && value.length > 0
}

export function isNonEmptyArray<T>(value: unknown): value is T[] {
  return Array.isArray(value) && value.length > 0
}
