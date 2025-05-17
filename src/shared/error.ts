import { HttpStatus } from '@nestjs/common'
import { ApiException, ErrorDetailMessage } from 'src/shared/exceptions/api.exception'

// entityNameKey: ví dụ 'Error.Resource.Language',
// args: ví dụ { id: 123 } để i18n có thể dịch thành "Ngôn ngữ với ID 123 không tìm thấy"
export const NotFoundRecordException = (
  messageKey: string = 'Error.Global.NotFound',
  errorCode: string = 'RESOURCE_NOT_FOUND',
  details?: ErrorDetailMessage[] | ErrorDetailMessage // Cho phép truyền một ErrorDetailMessage hoặc một mảng
) =>
  new ApiException(
    HttpStatus.NOT_FOUND,
    errorCode,
    messageKey,
    // Nếu details được cung cấp, dùng nó (đảm bảo là array nếu là object đơn).
    // Nếu không, tạo một detail mặc định sử dụng messageKey.
    details ? (Array.isArray(details) ? details : [details]) : [{ code: messageKey || 'Error.Global.NotFound' }] // Đảm bảo code luôn là string
  )
