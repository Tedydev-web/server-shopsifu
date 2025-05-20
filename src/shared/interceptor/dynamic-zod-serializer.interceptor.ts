import { CallHandler, ExecutionContext, Injectable, NestInterceptor } from '@nestjs/common'
import { Observable } from 'rxjs'
import { map } from 'rxjs/operators'
import { ZodType } from 'zod'
import { ZodSerializationException } from 'nestjs-zod'

export interface SchemaOption {
  schema: ZodType
  predicate: (data: any) => boolean
}

@Injectable()
export class DynamicZodSerializerInterceptor implements NestInterceptor {
  constructor(private readonly schemas: SchemaOption[]) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    return next.handle().pipe(
      map((data) => {
        if (data === undefined || data === null) {
          return data
        }

        const schemaOption = this.schemas.find((option) => option.predicate(data))

        if (!schemaOption) {
          return data
        }

        const schema = schemaOption.schema
        const result = schema.safeParse(data)

        if (!result.success) {
          const { error } = result
          throw new ZodSerializationException(error)
        }

        return result.data
      })
    )
  }
}

export function DynamicZodSerializer(...schemas: SchemaOption[]) {
  return function (target: any, key: string, descriptor: PropertyDescriptor) {
    const originalMethod = descriptor.value

    descriptor.value = function (...args: any[]) {
      const result = originalMethod.apply(this, args)

      if (result instanceof Promise) {
        return result.then((data) => {
          const validSchema = schemas.find((schema) => schema.predicate(data))

          if (!validSchema) {
            return data
          }

          const validationResult = validSchema.schema.safeParse(data)

          if (!validationResult.success) {
            throw new ZodSerializationException(validationResult.error)
          }

          return validationResult.data
        })
      }

      return result
    }

    return descriptor
  }
}
