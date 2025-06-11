import { Module, Global } from '@nestjs/common'
import { ClsModule as NestClsModule } from 'nestjs-cls'

@Global()
@Module({
  imports: [
    NestClsModule.forRoot({
      global: true,
      middleware: {
        mount: true
        // Let's see if this is needed, start without it.
        // generateId: true,
        // idGenerator: (req: Request) => req.headers['x-request-id'] ?? v4(),
      }
    })
  ],
  exports: [NestClsModule]
})
export class ClsModule {}
