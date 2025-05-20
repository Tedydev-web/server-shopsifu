import { HttpException, HttpStatus } from '@nestjs/common'

export interface ErrorDetailMessage {
  path?: string
  code: string
  value?: any
  args?: Record<string, any>
}

export class ApiException extends HttpException {
  public readonly errorCode: string
  public readonly details: ErrorDetailMessage[]

  constructor(
    httpStatus: HttpStatus,
    errorCode: string,
    messageKey: string,
    details?: ErrorDetailMessage[] | ErrorDetailMessage
  ) {
    super(messageKey, httpStatus)
    this.errorCode = errorCode

    if (details) {
      this.details = Array.isArray(details) ? details : [details]
    } else {
      this.details = []
    }
    this.name = this.constructor.name
  }
}
