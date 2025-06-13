export interface FieldError {
  field: string
  description: string
}

export interface ErrorResponseDto {
  status: number
  message: string
  errors?: FieldError[]
  canRetry?: boolean
  details?: any
}

export interface ValidationErrorDto extends ErrorResponseDto {
  status: 422
  errors: FieldError[]
}

export interface AuthenticationErrorDto extends ErrorResponseDto {
  status: 401
  canRetry: false
}

export interface VerificationErrorDto extends ErrorResponseDto {
  status: 400
  canRetry: boolean
  field?: string
}
