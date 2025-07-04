import { Module } from '@nestjs/common'
import { CartController } from './cart.controller'
import { CartService } from './cart.service'
import { CartRepo } from './cart.repo'
import { PaginationService } from 'src/shared/services/pagination.service'

@Module({
  providers: [CartService, CartRepo, PaginationService],
  controllers: [CartController],
})
export class CartModule {}
