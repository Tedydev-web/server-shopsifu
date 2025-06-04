import { Controller, Get } from '@nestjs/common'
import { IsPublic } from './shared/decorators/auth.decorator'
import { AppService } from './app.service'

@Controller()
export class AppController {
  constructor(private readonly appService: AppService) {}

  @IsPublic()
  @Get('get-cookies')
  getHello(): string {
    return this.appService.getHello()
  }
}
