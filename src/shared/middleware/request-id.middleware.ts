import { Injectable, NestMiddleware } from '@nestjs/common'
import { Request, Response, NextFunction } from 'express'
import { v4 as uuidv4 } from 'uuid'

@Injectable()
export class RequestIdMiddleware implements NestMiddleware {
  use(req: Request, res: Response, next: NextFunction) {
    // Sử dụng req['id'] để tránh lỗi type checking với Express.Request mặc định
    // Hoặc có thể khai báo một interface tùy chỉnh mở rộng Express.Request
    if (!req['id']) {
      req['id'] = uuidv4()
    }
    next()
  }
}
