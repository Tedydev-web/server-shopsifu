import { z } from 'zod'

export const ProvinceSchema = z.object({
  ProvinceID: z.number(),
  ProvinceName: z.string(),
  Code: z.string().optional(),
  CountryID: z.number().optional(),
  Extension: z.string().optional()
})

export const DistrictSchema = z.object({
  DistrictID: z.number(),
  ProvinceID: z.number(),
  DistrictName: z.string(),
  Code: z.string().optional(),
  Extension: z.string().optional()
})

export const WardSchema = z.object({
  WardCode: z.string(),
  DistrictID: z.number(),
  WardName: z.string(),
  Extension: z.string().optional()
})

export const ServiceSchema = z.object({
  service_id: z.number(),
  short_name: z.string(),
  service_type_id: z.number(),
  config_fee_id: z.string().nullable().optional(),
  extra_cost_id: z.string().nullable().optional(),
  standard_config_fee_id: z.string().nullable().optional(),
  standard_extra_cost_id: z.string().nullable().optional()
})

export const CalculateShippingFeeSchema = z.object({
  height: z.number().positive(),
  weight: z.number().positive(),
  length: z.number().positive(),
  width: z.number().positive(),
  service_type_id: z.number().optional(),
  service_id: z.number().optional(),
  insurance_value: z.number().optional(),
  coupon: z.string().optional(),
  cod_failed_amount: z.number().optional(),
  cod_value: z.number().optional(),
  cartItemId: z.string().optional()
})

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

export const GetDistrictsQuerySchema = z.object({
  provinceId: z.coerce.number().int().positive()
})

export const GetWardsQuerySchema = z.object({
  districtId: z.coerce.number().int().positive()
})

export const GetServiceListQuerySchema = z.object({
  cartItemId: z.string().optional()
})

export const CalculateExpectedDeliveryTimeSchema = z.object({
  service_id: z.number(),
  cartItemId: z.string().optional()
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
  shippingFee: z.number().optional(),
  content: z.string().optional(),
  weight: z.number(),
  length: z.number(),
  width: z.number(),
  height: z.number(),
  pick_station_id: z.number().optional(),
  insurance_value: z.number().optional(),
  service_id: z.number().optional(),
  service_type_id: z.number().optional(),
  config_fee_id: z.string().optional(),
  extra_cost_id: z.string().optional(),
  coupon: z.string().nullable().optional(),
  pick_shift: z.number().array().optional(),
  items: z
    .object({
      name: z.string(),
      quantity: z.number(),
      weight: z.number(),
      length: z.number().optional(),
      width: z.number().optional(),
      height: z.number().optional()
    })
    .array(),
  payment_type_id: z.number(),
  note: z.string().optional(),
  required_note: z.string().optional()
})

export const GHNWebhookPayloadSchema = z.object({
  // GHN API fields (camelCase only - theo tài liệu chính thức)
  orderCode: z.string().optional(),
  status: z.string().optional(),
  Type: z.string().optional(),
  Time: z.string().optional(),
  ShopID: z.number().optional(),
  ClientOrderCode: z.string().optional(),
  CODAmount: z.number().optional(),
  Weight: z.number().optional(),
  Length: z.number().optional(),
  Width: z.number().optional(),
  Height: z.number().optional(),
  Description: z.string().optional(),
  PaymentType: z.number().optional(),
  TotalFee: z.number().optional(),
  Warehouse: z.string().optional(),
  IsPartialReturn: z.boolean().optional(),
  PartialReturnCode: z.string().optional(),
  Reason: z.string().optional(),
  ReasonCode: z.string().optional(),
  ConvertedWeight: z.number().optional(),
  CODTransferDate: z.string().nullable().optional(),

  // Fee object (camelCase only)
  Fee: z
    .object({
      MainService: z.number().optional(),
      Insurance: z.number().optional(),
      StationDO: z.number().optional(),
      StationPU: z.number().optional(),
      Return: z.number().optional(),
      R2S: z.number().optional(),
      Coupon: z.number().optional(),
      DocumentReturn: z.number().optional(),
      DoubleCheck: z.number().optional(),
      DoubleCheckDeliver: z.number().optional(),
      PickRemoteAreasFee: z.number().optional(),
      DeliverRemoteAreasFee: z.number().optional(),
      PickRemoteAreasFeeReturn: z.number().optional(),
      DeliverRemoteAreasFeeReturn: z.number().optional(),
      CODFailedFee: z.number().optional(),
      Total: z.number().optional()
    })
    .optional()
})

export const GHNWebhookResponseSchema = z.object({
  // GHN yêu cầu response code = 200 và JSON format
  // Response này sẽ được GHN nhận để xác nhận webhook đã được xử lý
  message: z.string(),
  code: z.number().default(200),
  timestamp: z.string().optional(),
  orderCode: z.string().optional(),
  status: z.string().optional()
})

export const GetOrderInfoQuerySchema = z.object({
  orderCode: z.string().min(1, 'Order code is required')
})

export const OrderInfoDataSchema = z.object({
  // Basic order info
  order_code: z.string(),
  client_order_code: z.string().nullable(),
  status: z.string(),
  created_date: z.union([z.string(), z.date()]),
  updated_date: z.union([z.string(), z.date()]),

  // From info (sender/shop)
  from_name: z.string(),
  from_phone: z.string(),
  from_address: z.string(),
  from_ward_code: z.string(),
  from_district_id: z.number(),

  // To info (receiver/customer)
  to_name: z.string(),
  to_phone: z.string(),
  to_address: z.string(),
  to_ward_code: z.string(),
  to_district_id: z.number(),

  // Package info
  weight: z.number(),
  converted_weight: z.number().nullable().optional(),
  length: z.number(),
  width: z.number(),
  height: z.number(),
  content: z.string().nullable().optional(),

  // Service info
  service_id: z.number(),
  service_type_id: z.number(),
  payment_type_id: z.number(),
  cod_amount: z.number().nullable().optional(),
  insurance_value: z.number().nullable().optional(),
  order_value: z.number().nullable().optional(),

  // Timing info
  order_date: z.union([z.string(), z.date()]).nullable().optional(),
  leadtime: z.union([z.string(), z.date()]).nullable().optional(),
  finish_date: z.union([z.string(), z.date()]).nullable().optional(),

  // status & tracking
  pick_warehouse_id: z.number().nullable().optional(),
  deliver_warehouse_id: z.number().nullable().optional(),
  current_warehouse_id: z.number().nullable().optional(),
  log: z.unknown().array().optional(),
  tag: z.string().array().optional(),

  // Additional useful fields
  note: z.string().nullable().optional(),
  required_note: z.string().nullable().optional()
})

export const GetOrderInfoResSchema = z.object({
  message: z.string().optional(),
  data: OrderInfoDataSchema
})

// Schema cho Tracking URL
export const GetTrackingUrlQuerySchema = z.object({
  orderCode: z.string().min(1, 'Order code is required')
})

export const GetTrackingUrlResSchema = z.object({
  message: z.string().optional(),
  data: z.object({
    trackingUrl: z.string(),
    orderCode: z.string()
  })
})

export const CreateOrderResSchema = PreviewOrderResSchema

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

export type GetOrderInfoQueryType = z.infer<typeof GetOrderInfoQuerySchema>
export type OrderInfoDataType = z.infer<typeof OrderInfoDataSchema>
export type GetOrderInfoResType = z.infer<typeof GetOrderInfoResSchema>

export const PrintOrderResSchema = z.object({
  message: z.string().optional(),
  data: z.object({
    token: z.string(),
    printUrls: z.object({
      a5: z.string(),
      '80x80': z.string(),
      '50x72': z.string()
    })
  })
})

export type PrintOrderResType = z.infer<typeof PrintOrderResSchema>

export type GetTrackingUrlQueryType = z.infer<typeof GetTrackingUrlQuerySchema>
export type GetTrackingUrlResType = z.infer<typeof GetTrackingUrlResSchema>
