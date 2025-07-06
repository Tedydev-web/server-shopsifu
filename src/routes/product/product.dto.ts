import { createZodDto } from 'nestjs-zod'
import {
  CreateProductBodySchema,
  GetProductDetailResSchema,
  GetProductParamsSchema,
  GetProductsResSchema,
  UpdateProductBodySchema
} from 'src/routes/product/product.model'
import { ProductSchema } from 'src/shared/models/shared-product.model'

export class ProductDTO extends createZodDto(ProductSchema) {}

export class GetProductsResDTO extends createZodDto(GetProductsResSchema) {}

export class GetProductParamsDTO extends createZodDto(GetProductParamsSchema) {}

export class GetProductDetailResDTO extends createZodDto(GetProductDetailResSchema) {}

export class CreateProductBodyDTO extends createZodDto(CreateProductBodySchema) {}

export class UpdateProductBodyDTO extends createZodDto(UpdateProductBodySchema) {}
