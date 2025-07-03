import { Module } from '@nestjs/common'
import { ProductController } from 'src/routes/product/product.controller'
import { ProductRepo } from 'src/routes/product/product.repo'
import { ProductService } from 'src/routes/product/product.service'

@Module({
  providers: [ProductService, ProductRepo],
  controllers: [ProductController],
})
export class ProductModule {}
