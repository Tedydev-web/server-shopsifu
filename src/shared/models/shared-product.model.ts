import { z } from 'zod'

export const VariantSchema = z.object({
  value: z.string().trim(),
  options: z.array(z.string().trim())
})

export const VariantsSchema = z.array(VariantSchema).superRefine((variants, ctx) => {
  // Kiểm tra variants và variant option có bị trùng hay không
  for (let i = 0; i < variants.length; i++) {
    const variant = variants[i]
    const isExistingVariant = variants.findIndex((v) => v.value.toLowerCase() === variant.value.toLowerCase()) !== i
    if (isExistingVariant) {
      return ctx.addIssue({
        code: 'custom',
        message: `Giá trị ${variant.value} đã tồn tại trong danh sách variants. Vui lòng kiểm tra lại.`,
        path: ['variants']
      })
    }
    const isDifferentOption = variant.options.some((option, index) => {
      const isExistingOption = variant.options.findIndex((o) => o.toLowerCase() === option.toLowerCase()) !== index
      return isExistingOption
    })
    if (isDifferentOption) {
      return ctx.addIssue({
        code: 'custom',
        message: `Variant ${variant.value} chứa các option trùng tên với nhau. Vui lòng kiểm tra lại.`,
        path: ['variants']
      })
    }
  }
})

export const SpecificationSchema = z.object({
  name: z.string().trim(),
  value: z.string().trim()
})

export const SpecificationsSchema = z.array(SpecificationSchema).superRefine((specs, ctx) => {
  // Loại bỏ các specifications trùng lặp thay vì báo lỗi
  const uniqueSpecs = specs.filter(
    (spec, index, self) => index === self.findIndex((s) => s.name.toLowerCase() === spec.name.toLowerCase())
  )

  // Nếu có trùng lặp, thay thế bằng danh sách đã loại bỏ trùng lặp
  if (uniqueSpecs.length !== specs.length) {
    // Thay thế specs bằng uniqueSpecs
    specs.length = 0
    specs.push(...uniqueSpecs)
  }
})

export const ProductSchema = z.object({
  id: z.string(),
  publishedAt: z.coerce.date().nullable(),
  name: z.string().trim().max(500),
  description: z.string().default(''),
  basePrice: z.number().min(0),
  virtualPrice: z.number().min(0),
  brandId: z.string(),
  images: z.array(z.string()),
  variants: VariantsSchema, // Json field represented as a record
  specifications: SpecificationsSchema.nullable().default([]),
  createdById: z.string().nullable(),
  updatedById: z.string().nullable(),
  deletedById: z.string().nullable(),
  deletedAt: z.union([z.string(), z.date()]).nullable(),
  createdAt: z.union([z.string(), z.date()]),
  updatedAt: z.union([z.string(), z.date()])
})

export type ProductType = z.infer<typeof ProductSchema>
export type VariantsType = z.infer<typeof VariantsSchema>
export type SpecificationsType = z.infer<typeof SpecificationsSchema>
