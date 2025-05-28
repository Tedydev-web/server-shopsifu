import { IsNotEmpty, IsOptional, IsString } from 'class-validator'
import { z } from 'zod'

export class LinkGoogleAccountReqDto {
  @IsString()
  @IsNotEmpty()
  googleId: string

  @IsOptional()
  @IsString()
  googleEmail?: string

  @IsOptional()
  @IsString()
  googleName?: string

  @IsOptional()
  @IsString()
  googleAvatar?: string
}

export const LinkGoogleAccountReqSchema = z.object({
  googleId: z.string().min(1),
  googleEmail: z.string().optional(),
  googleName: z.string().optional().nullable(),
  googleAvatar: z.string().optional().nullable()
})
