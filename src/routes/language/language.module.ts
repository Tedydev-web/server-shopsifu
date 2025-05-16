import { Module } from '@nestjs/common'
import { LanguageService } from './language.service'
import { LanguageController } from './language.controller'
import { LanguageRepo } from './language.repo'

@Module({
  providers: [LanguageService, LanguageRepo],
  controllers: [LanguageController]
})
export class LanguageModule {}
