import { Module } from '@nestjs/common'
import { LanguageController } from './language.controller'
import { LanguageService } from './language.service'
import { LanguageRepo } from './language.repo'

@Module({
  controllers: [LanguageController],
  providers: [LanguageService, LanguageRepo],
  exports: [LanguageService, LanguageRepo],
})
export class LanguageModule {}
