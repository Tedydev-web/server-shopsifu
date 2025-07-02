import { Module } from '@nestjs/common'
import { CategoryTranslationController } from 'src/routes/category/category-translation/category-translation.controller'
import { CategoryTranslationRepo } from 'src/routes/category/category-translation/category-translation.repo'
import { CategoryTranslationService } from 'src/routes/category/category-translation/category-translation.service'

@Module({
  providers: [CategoryTranslationRepo, CategoryTranslationService],
  controllers: [CategoryTranslationController],
})
export class CategoryTranslationModule {}
