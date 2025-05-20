import { HttpStatus } from '@nestjs/common'
import { ApiException } from 'src/shared/exceptions/api.exception'

// Lỗi khi đã tồn tại ngôn ngữ
export const LanguageAlreadyExistsException = new ApiException(
  HttpStatus.CONFLICT,
  'RESOURCE_CONFLICT',
  'Error.Language.AlreadyExists',
  [{ code: 'Error.Language.AlreadyExists', path: 'id' }]
)

// Lỗi khi không tìm thấy ngôn ngữ (chi tiết hơn với tham số)
export const LanguageNotFoundException = (languageId: string) =>
  new ApiException(HttpStatus.NOT_FOUND, 'RESOURCE_NOT_FOUND', 'Error.Language.NotFound', [
    { code: 'Error.Language.NotFound', path: 'languageId', args: { id: languageId } }
  ])

// Lỗi khi ngôn ngữ đã bị xóa (soft delete)
export const LanguageDeletedException = (languageId: string) =>
  new ApiException(HttpStatus.GONE, 'RESOURCE_DELETED', 'Error.Language.Deleted', [
    { code: 'Error.Language.Deleted', path: 'languageId', args: { id: languageId } }
  ])

// Lỗi khi ngôn ngữ đang được sử dụng bởi các bản ghi khác
export const LanguageInUseException = (languageId: string) =>
  new ApiException(HttpStatus.CONFLICT, 'RESOURCE_IN_USE', 'Error.Language.InUse', [
    { code: 'Error.Language.InUse', path: 'languageId', args: { id: languageId } }
  ])

// Lỗi khi định dạng ID ngôn ngữ không hợp lệ
export const InvalidLanguageFormatException = new ApiException(
  HttpStatus.UNPROCESSABLE_ENTITY,
  'VALIDATION_ERROR',
  'Error.Language.InvalidFormat',
  [{ code: 'Error.Language.InvalidFormat', path: 'id' }]
)

// Lỗi khi người dùng không có quyền thực hiện hành động
export const LanguageActionForbiddenException = new ApiException(
  HttpStatus.FORBIDDEN,
  'FORBIDDEN',
  'Error.Language.ActionForbidden',
  [{ code: 'Error.Language.ActionForbidden' }]
)
