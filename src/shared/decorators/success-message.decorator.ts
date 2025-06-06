import { SetMetadata } from '@nestjs/common'
import { I18nPath } from 'src/generated/i18n.generated'

export const SUCCESS_MESSAGE_KEY = 'success_message'

/**
 * Decorator to set a standardized success message for an API endpoint.
 * The message should be an i18n key.
 * @param message The i18n key for the success message.
 */
export const SuccessMessage = (message: I18nPath) => SetMetadata(SUCCESS_MESSAGE_KEY, message)
