import { createZodDto } from 'nestjs-zod'
import { MessageResSchema } from 'src/shared/models/response.model'

export class MessageResDTO extends createZodDto(MessageResSchema) {}
