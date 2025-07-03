import { createZodDto } from 'nestjs-zod'
import {
  CreateProductBodySchema,
  GetProductDetailResSchema,
  GetProductParamsSchema,
  GetProductsQuerySchema,
  GetProductsResSchema,
  ProductSchema,
  UpdateProductBodySchema,
} from 'src/routes/product/product.model'

export class ProductDTO extends createZodDto(ProductSchema) {}

export class GetProductsResDTO extends createZodDto(GetProductsResSchema) {}

export class GetProductsQueryDTO extends createZodDto(GetProductsQuerySchema) {}

export class GetProductParamsDTO extends createZodDto(GetProductParamsSchema) {}

export class GetProductDetailResDTO extends createZodDto(GetProductDetailResSchema) {}

export class CreateProductBodyDTO extends createZodDto(CreateProductBodySchema) {}

export class UpdateProductBodyDTO extends createZodDto(UpdateProductBodySchema) {}
