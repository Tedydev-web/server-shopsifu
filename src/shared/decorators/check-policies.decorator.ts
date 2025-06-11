import { SetMetadata, Type } from '@nestjs/common'
import { IPolicyHandler, PolicyHandler, PolicyHandlerCallback } from '../providers/casl/casl.types'

export const CHECK_POLICIES_KEY = 'check_policy'

/**
 * Decorator to apply policy checks to a route handler.
 * @param handlers - A list of policy handlers to be executed.
 */
export const CheckPolicies = (...handlers: Array<Type<IPolicyHandler> | PolicyHandlerCallback>) =>
  SetMetadata(CHECK_POLICIES_KEY, handlers)
