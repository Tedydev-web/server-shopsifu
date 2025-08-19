import { createZodDto } from 'nestjs-zod'
import {
  UploadFilesResSchema,
  BatchPresignedUploadBodySchema,
  BatchPresignedUploadResSchema
} from 'src/routes/media/media.model'

export class UploadFilesResDTO extends createZodDto(UploadFilesResSchema) {}

export class BatchPresignedUploadBodyDTO extends createZodDto(BatchPresignedUploadBodySchema) {}

export class BatchPresignedUploadResDTO extends createZodDto(BatchPresignedUploadResSchema) {}
