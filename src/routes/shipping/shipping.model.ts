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

// Schema cho Service (dịch vụ vận chuyển) - khớp với GetServiceResponse thực tế
export const ServiceSchema = z.object({
  service_id: z.number(),
  short_name: z.string(),
  service_type_id: z.number(),
  config_fee_id: z.string().optional(), // Có thể undefined
  extra_cost_id: z.string().optional(), // Có thể undefined
  standard_config_fee_id: z.string().optional(), // Có thể undefined
  standard_extra_cost_id: z.string().optional() // Có thể undefined
})

// Schema cho CalculateShippingFee request - khớp với CalculateShippingFee
export const CalculateShippingFeeSchema = z.object({
  to_district_id: z.number(),
  to_ward_code: z.string(),
  height: z.number().positive(),
  weight: z.number().positive(),
  length: z.number().positive(),
  width: z.number().positive(),
  service_type_id: z.number().optional(),
  service_id: z.number().optional(),
  from_district_id: z.number().optional(),
  from_ward_code: z.string().optional(),
  insurance_value: z.number().optional(),
  coupon: z.string().optional(),
  cod_failed_amount: z.number().optional(),
  cod_value: z.number().optional()
})

// Schema cho CalculateShippingFee response - khớp với CalculateShippingFeeResponse thực tế
export const CalculateShippingFeeResponseSchema = z.object({
  total: z.number(),
  service_fee: z.number(),
  insurance_fee: z.number(),
  pick_station_fee: z.number().optional(), // Có thể undefined
  coupon_value: z.number().optional(), // Có thể undefined
  r2s_fee: z.number().optional(), // Có thể undefined
  document_return: z.number().optional(), // Có thể undefined
  double_check: z.number().optional(), // Có thể undefined
  cod_fee: z.number().optional(), // Có thể undefined
  pick_remote_areas_fee: z.number().optional(), // Có thể undefined
  deliver_remote_areas_fee: z.number().optional(), // Có thể undefined
  cod_failed_fee: z.number().optional() // Có thể undefined
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

export const GetServiceListResSchema = z.object({
  message: z.string().optional(),
  data: z.array(ServiceSchema)
})

export const CalculateShippingFeeResSchema = z.object({
  message: z.string().optional(),
  data: CalculateShippingFeeResponseSchema
})

// Query schemas
export const GetDistrictsQuerySchema = z.object({
  provinceId: z.coerce.number().int().positive()
})

export const GetWardsQuerySchema = z.object({
  districtId: z.coerce.number().int().positive()
})

export const GetServiceListQuerySchema = z.object({
  fromDistrictId: z.coerce.number().int().positive(),
  toDistrictId: z.coerce.number().int().positive()
})

// Type exports
export type ProvinceType = z.infer<typeof ProvinceSchema>
export type DistrictType = z.infer<typeof DistrictSchema>
export type WardType = z.infer<typeof WardSchema>
export type ServiceType = z.infer<typeof ServiceSchema>
export type CalculateShippingFeeType = z.infer<typeof CalculateShippingFeeSchema>
export type CalculateShippingFeeResponseType = z.infer<typeof CalculateShippingFeeResponseSchema>

export type GetProvincesResType = z.infer<typeof GetProvincesResSchema>
export type GetDistrictsResType = z.infer<typeof GetDistrictsResSchema>
export type GetWardsResType = z.infer<typeof GetWardsResSchema>
export type GetServiceListResType = z.infer<typeof GetServiceListResSchema>
export type CalculateShippingFeeResType = z.infer<typeof CalculateShippingFeeResSchema>

export type GetDistrictsQueryType = z.infer<typeof GetDistrictsQuerySchema>
export type GetWardsQueryType = z.infer<typeof GetWardsQuerySchema>
export type GetServiceListQueryType = z.infer<typeof GetServiceListQuerySchema>
