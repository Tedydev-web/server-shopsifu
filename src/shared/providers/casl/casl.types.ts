import { AppAbility } from './casl-ability.factory'

/**
 * Interface for a policy handler that can be class-based.
 */
export interface IPolicyHandler {
  handle(ability: AppAbility, request: any): boolean | Promise<boolean>
}

/**
 * Type for a policy handler that is a function.
 */
export type PolicyHandlerCallback = (ability: AppAbility, request: any) => boolean | Promise<boolean>

/**
 * Union type for all possible policy handlers.
 */
export type PolicyHandler = IPolicyHandler | PolicyHandlerCallback
