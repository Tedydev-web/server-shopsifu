import { z } from 'zod'

export const PaymentTransactionSchema = z.object({
  id: z.string(),
  gateway: z.string(),
  transactionDate: z.date(),
  accountNumber: z.string().nullable(),
  subAccount: z.string().nullable(),
  amountIn: z.number(),
  amountOut: z.number(),
  accumulated: z.number(),
  code: z.string().nullable(),
  transactionContent: z.string().nullable(),
  referenceNumber: z.string().nullable(),
  body: z.string().nullable(),
  createdAt: z.date()
})

export type PaymentTransactionType = z.infer<typeof PaymentTransactionSchema>
