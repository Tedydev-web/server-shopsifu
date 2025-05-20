import { HttpStatus } from '@nestjs/common'
import { ApiException, ErrorDetailMessage } from 'src/shared/exceptions/api.exception'

export const NotFoundRecordException = (
  messageKey: string = 'Error.Global.NotFound',
  errorCode: string = 'RESOURCE_NOT_FOUND',
  details?: ErrorDetailMessage[] | ErrorDetailMessage
) =>
  new ApiException(
    HttpStatus.NOT_FOUND,
    errorCode,
    messageKey,

    details ? (Array.isArray(details) ? details : [details]) : [{ code: messageKey || 'Error.Global.NotFound' }]
  )
