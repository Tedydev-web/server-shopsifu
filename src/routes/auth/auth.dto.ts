import { createZodDto } from 'nestjs-zod'
<<<<<<< HEAD
import { RegisterBodySchema, RegisterResSchema } from 'src/routes/auth/auth.model'
=======
import { RegisterBodySchema, RegisterResSchema, SendOTPBodySchema } from 'src/routes/auth/auth.model'
>>>>>>> feature/3-users-auth-otp

export class RegisterBodyDTO extends createZodDto(RegisterBodySchema) {}

export class RegisterResDTO extends createZodDto(RegisterResSchema) {}
<<<<<<< HEAD
=======

export class SendOTPBodyDTO extends createZodDto(SendOTPBodySchema) {}
>>>>>>> feature/3-users-auth-otp
