import { createZodDto } from 'nestjs-zod'
import {
  CreateReviewBodySchema,
  CreateReviewResSchema,
  GetReviewDetailParamsSchema,
  GetReviewsParamsSchema,
  GetReviewsSchema,
  UpdateReviewBodySchema,
  UpdateReviewResSchema,
} from 'src/routes/review/review.model'

export class GetReviewsDTO extends createZodDto(GetReviewsSchema) {}
export class CreateReviewBodyDTO extends createZodDto(CreateReviewBodySchema) {}
export class CreateReviewResDTO extends createZodDto(CreateReviewResSchema) {}
export class UpdateReviewBodyDTO extends createZodDto(UpdateReviewBodySchema) {}
export class UpdateReviewResDTO extends createZodDto(UpdateReviewResSchema) {}
export class GetReviewsParamsDTO extends createZodDto(GetReviewsParamsSchema) {}
export class GetReviewDetailParamsDTO extends createZodDto(GetReviewDetailParamsSchema) {}
