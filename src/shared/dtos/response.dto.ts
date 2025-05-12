import { createZodDto } from 'nestjs-zod'
import { ApiResponseSchema, MessageResSchema } from 'src/shared/models/reponse.model'

export class MessageResDTO extends createZodDto(MessageResSchema) {}
export class ApiResponseDTO extends createZodDto(ApiResponseSchema) {}
