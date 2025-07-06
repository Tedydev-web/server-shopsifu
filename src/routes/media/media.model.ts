import { z } from 'zod'

export const PresignedUploadFileBodySchema = z
  .object({
    filename: z.string(),
    filesize: z.number().max(1 * 1024 * 1024) // 1MB
  })
  .strict()

export const UploadFilesResSchema = z.object({
  message: z.string(),
  data: z.array(
    z.object({
      url: z.string()
    })
  )
})

export const PresignedUploadFileResSchema = z.object({
  message: z.string(),
  presignedUrl: z.string(),
  url: z.string()
})

export type PresignedUploadFileBodyType = z.infer<typeof PresignedUploadFileBodySchema>
