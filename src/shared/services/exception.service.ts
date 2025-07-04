import { Injectable, OnModuleInit } from '@nestjs/common'
import { I18nService } from 'nestjs-i18n'
import { I18nTranslations } from 'src/generated/i18n.generated'
import { ExceptionFactory } from 'src/shared/error'

@Injectable()
export class ExceptionService implements OnModuleInit {
  constructor(private readonly i18n: I18nService<I18nTranslations>) {}

  onModuleInit() {
    // Khởi tạo ExceptionFactory với i18n service
    ExceptionFactory.setI18n(this.i18n)
  }
} 