import { SetMetadata } from '@nestjs/common'

export const RESPONSE_MESSAGE_KEY = 'responseMessage'

/**
 * Decorator để đặt i18n key cho thông điệp thành công của response.
 * Interceptor sẽ sử dụng key này để dịch thông điệp.
 * @param messageKey Key i18n cho thông điệp thành công.
 */
export const ResponseMessage = (messageKey: string) => SetMetadata(RESPONSE_MESSAGE_KEY, messageKey)
