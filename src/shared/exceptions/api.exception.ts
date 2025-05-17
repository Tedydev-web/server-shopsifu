import { HttpException, HttpStatus } from '@nestjs/common';

export interface ErrorDetailMessage {
  path?: string;
  code: string; // i18n key for specific field error or a more detailed reason
  value?: any; // Submitted value causing the error (use with caution for sensitive data)
  args?: Record<string, any>; // Arguments for i18n message formatting
}

export class ApiException extends HttpException {
  public readonly errorCode: string; // General error type code like VALIDATION_ERROR
  public readonly details: ErrorDetailMessage[];

  constructor(
    httpStatus: HttpStatus,
    errorCode: string, // e.g., VALIDATION_ERROR, UNAUTHENTICATED
    messageKey: string, // This will be the primary i18n key for the error
    details?: ErrorDetailMessage[] | ErrorDetailMessage,
  ) {
    // The 'messageKey' is passed to HttpException, our custom filter will use it as the main i18n key.
    // The 'errorCode' and 'details' are custom properties.
    super(messageKey, httpStatus); 
    this.errorCode = errorCode;
    
    if (details) {
      this.details = Array.isArray(details) ? details : [details];
    } else {
      // If no specific details are provided, the main messageKey itself can be considered the detail.
      this.details = []; 
    }
    this.name = this.constructor.name; // Better for logging
  }
} 