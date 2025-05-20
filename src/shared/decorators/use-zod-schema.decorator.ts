import { UseInterceptors, applyDecorators } from '@nestjs/common'
import {
  DynamicZodSerializerInterceptor,
  SchemaOption
} from 'src/shared/interceptor/dynamic-zod-serializer.interceptor'
import { ZodType } from 'zod'

export function UseZodSchemas(...schemas: SchemaOption[]) {
  return applyDecorators(UseInterceptors(new DynamicZodSerializerInterceptor(schemas)))
}

export function createSchemaOption<T>(schema: ZodType<T>, predicate: (data: any) => boolean): SchemaOption {
  return { schema, predicate }
}

export const hasProperty = (property: string) => (data: any) =>
  data !== null && typeof data === 'object' && property in data

export const hasAllProperties =
  (...properties: string[]) =>
  (data: any) =>
    data !== null && typeof data === 'object' && properties.every((prop) => prop in data)

export const hasAnyProperty =
  (...properties: string[]) =>
  (data: any) =>
    data !== null && typeof data === 'object' && properties.some((prop) => prop in data)
