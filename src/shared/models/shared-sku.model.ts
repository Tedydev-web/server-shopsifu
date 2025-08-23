import { z } from 'zod'

export const SKUSchema = z.object({
  id: z.string(),
  value: z.string().trim(),
  price: z.number().min(0),
  stock: z.number().min(0),
  image: z.string(),
  productId: z.string(),

  createdById: z.string(),
  updatedById: z.string().nullable(),
  deletedById: z.string().nullable(),
  deletedAt: z.union([z.string(), z.date()]).nullable(),
  createdAt: z.union([z.string(), z.date()]),
  updatedAt: z.union([z.string(), z.date()])
})

export type SKUSchemaType = z.infer<typeof SKUSchema>
