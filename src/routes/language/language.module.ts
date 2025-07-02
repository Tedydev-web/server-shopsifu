import { Module } from '@nestjs/common'
import { LanguageController } from 'src/routes/language/language.controller'
import { LanguageRepo } from 'src/routes/language/language.repo'
import { LanguageService } from 'src/routes/language/language.service'
import { SharedModule } from 'src/shared/shared.module'

@Module({
  imports: [SharedModule],
  providers: [LanguageService, LanguageRepo],
  controllers: [LanguageController],
})
export class LanguageModule {}
