import { createZodDto } from 'nestjs-zod'
import { MessageResSchema } from 'src/shared/models/reponse.model'

export class MessageResDTO extends createZodDto(MessageResSchema) {}
