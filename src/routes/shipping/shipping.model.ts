import { z } from 'zod'

// Schema cho Province - GHN API có thể trả về undefined cho một số field
export const ProvinceSchema = z.object({
  ProvinceID: z.number(),
  ProvinceName: z.string(),
  Code: z.string().optional(), // Có thể undefined
  CountryID: z.number().optional(), // Có thể undefined
  Extension: z.string().optional()
})

// Schema cho District
export const DistrictSchema = z.object({
  DistrictID: z.number(),
  ProvinceID: z.number(),
  DistrictName: z.string(),
  Code: z.string().optional(), // Có thể undefined
  Extension: z.string().optional()
})

// Schema cho Ward
export const WardSchema = z.object({
  WardCode: z.string(),
  DistrictID: z.number(),
  WardName: z.string(),
  Extension: z.string().optional()
})

// Response schemas
export const GetProvincesResSchema = z.object({
  message: z.string().optional(),
  data: z.array(ProvinceSchema)
})

export const GetDistrictsResSchema = z.object({
  message: z.string().optional(),
  data: z.array(DistrictSchema)
})

export const GetWardsResSchema = z.object({
  message: z.string().optional(),
  data: z.array(WardSchema)
})

// Query schemas
export const GetDistrictsQuerySchema = z.object({
  provinceId: z.coerce.number().int().positive()
})

export const GetWardsQuerySchema = z.object({
  districtId: z.coerce.number().int().positive()
})

// Type exports
export type ProvinceType = z.infer<typeof ProvinceSchema>
export type DistrictType = z.infer<typeof DistrictSchema>
export type WardType = z.infer<typeof WardSchema>

export type GetProvincesResType = z.infer<typeof GetProvincesResSchema>
export type GetDistrictsResType = z.infer<typeof GetDistrictsResSchema>
export type GetWardsResType = z.infer<typeof GetWardsResSchema>

export type GetDistrictsQueryType = z.infer<typeof GetDistrictsQuerySchema>
export type GetWardsQueryType = z.infer<typeof GetWardsQuerySchema>
