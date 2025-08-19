import { z } from 'zod'

export const BatchPresignedUploadBodySchema = z.object({
  files: z
    .array(
      z.object({
        filename: z.string(),
        filesize: z.number().max(5 * 1024 * 1024) // 5MB per file
      })
    )
    .min(1)
    .max(100) // Giống như FilesInterceptor
})

export const UploadFilesResSchema = z.object({
  message: z.string().optional(),
  data: z.array(
    z.object({
      url: z.string()
    })
  )
})

export const BatchPresignedUploadResSchema = z.object({
  message: z.string().optional(),
  data: z.array(
    z.object({
      originalFilename: z.string(),
      filename: z.string(),
      presignedUrl: z.string(),
      url: z.string()
    })
  )
})

export type BatchPresignedUploadBodyType = z.infer<typeof BatchPresignedUploadBodySchema>
