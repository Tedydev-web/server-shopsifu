import { createZodDto } from 'nestjs-zod'
import { RegisterBodySchema, RegisterResSchema } from 'src/routes/auth/auth.model'

export class RegisterBodyDTO extends createZodDto(RegisterBodySchema) {}

export class RegisterResDTO extends createZodDto(RegisterResSchema) {}
