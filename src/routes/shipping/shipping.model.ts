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

// Schema cho Service (dịch vụ vận chuyển)
export const ServiceSchema = z.object({
  service_id: z.number(),
  short_name: z.string(),
  service_type_id: z.number(),
  config_fee_id: z.string().nullable().optional(),
  extra_cost_id: z.string().nullable().optional(),
  standard_config_fee_id: z.string().nullable().optional(),
  standard_extra_cost_id: z.string().nullable().optional()
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
  pick_station_fee: z.number().optional(),
  coupon_value: z.number().optional(),
  r2s_fee: z.number().optional(),
  document_return: z.number().optional(),
  double_check: z.number().optional(),
  cod_fee: z.number().optional(),
  pick_remote_areas_fee: z.number().optional(),
  deliver_remote_areas_fee: z.number().optional(),
  cod_failed_fee: z.number().optional()
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

// =============== Schema: Order Features (Phase 1) ===============
export const CalculateExpectedDeliveryTimeSchema = z.object({
  service_id: z.number(),
  to_district_id: z.number(),
  to_ward_code: z.string(),
  from_district_id: z.number(),
  from_ward_code: z.string()
})

export const CalculateExpectedDeliveryTimeResSchema = z.object({
  message: z.string().optional(),
  data: z.object({
    leadtime: z.number(),
    order_date: z.number().optional(),
    expected_delivery_time: z.string().optional()
  })
})

const FeeResponseSchema = z.object({
  main_service: z.number(),
  insurance: z.number(),
  station_do: z.number(),
  station_pu: z.number(),
  return: z.number(),
  r2s: z.number(),
  coupon: z.number(),
  document_return: z.number().optional(),
  double_check: z.number().optional(),
  double_check_deliver: z.number().optional(),
  pick_remote_areas_fee: z.number().optional(),
  deliver_remote_areas_fee: z.number().optional(),
  pick_remote_areas_fee_return: z.number().optional(),
  deliver_remote_areas_fee_return: z.number().optional(),
  cod_failed_fee: z.number().optional()
})

export const PreviewOrderResSchema = z.object({
  message: z.string().optional(),
  data: z.object({
    order_code: z.string(),
    sort_code: z.string(),
    trans_type: z.string(),
    total_fee: z.number(),
    expected_delivery_time: z.union([z.string(), z.date()]),
    fee: FeeResponseSchema,
    ward_encode: z.string().optional(),
    district_encode: z.string().optional(),
    operation_partner: z.string().optional()
  })
})

export const CreateOrderSchema = z.object({
  from_address: z.string(),
  from_name: z.string(),
  from_phone: z.string(),
  from_province_name: z.string(),
  from_district_name: z.string(),
  from_ward_name: z.string(),
  to_name: z.string(),
  to_phone: z.string(),
  to_address: z.string(),
  to_ward_code: z.string(),
  to_district_id: z.number(),
  client_order_code: z.string().nullable(),
  cod_amount: z.number().optional(),
  content: z.string().optional(),
  weight: z.number(),
  length: z.number(),
  width: z.number(),
  height: z.number(),
  pick_station_id: z.number().optional(),
  insurance_value: z.number().optional(),
  service_id: z.number().optional(),
  service_type_id: z.number().optional(),
  coupon: z.string().nullable().optional(),
  pick_shift: z.array(z.number()).optional(),
  items: z.array(
    z.object({
      name: z.string(),
      quantity: z.number(),
      weight: z.number(),
      length: z.number().optional(),
      width: z.number().optional(),
      height: z.number().optional()
    })
  ),
  payment_type_id: z.number(),
  note: z.string().optional(),
  required_note: z.string().optional()
})
// Schema cho webhook payload từ GHN
export const GHNWebhookPayloadSchema = z.object({
  OrderCode: z.string().optional(),
  order_code: z.string().optional(),
  Status: z.string().optional(),
  status: z.string().optional()
})

// Schema cho webhook response
export const GHNWebhookResponseSchema = z.object({
  message: z.string()
})

export const CreateOrderResSchema = PreviewOrderResSchema

// =============== Types ===============
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

export type CalculateExpectedDeliveryTimeType = z.infer<typeof CalculateExpectedDeliveryTimeSchema>
export type CalculateExpectedDeliveryTimeResType = z.infer<typeof CalculateExpectedDeliveryTimeResSchema>
export type PreviewOrderResType = z.infer<typeof PreviewOrderResSchema>
export type CreateOrderType = z.infer<typeof CreateOrderSchema>
export type CreateOrderResType = z.infer<typeof CreateOrderResSchema>

export type GHNWebhookPayloadType = z.infer<typeof GHNWebhookPayloadSchema>
export type GHNWebhookResponseType = z.infer<typeof GHNWebhookResponseSchema>
