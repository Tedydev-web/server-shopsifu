import { Injectable } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import * as dotenv from 'dotenv';
import * as crypto from 'crypto';
import * as qs from 'qs';

dotenv.config()

@Injectable()
export class VnpayService {



    constructor(
        private readonly config: ConfigService
    ) { }

    createPaymentUrl(orderId: string, amount: number, ip: string): string {
        const tmnCode = process.env.VNP_TMNCODE
        const secret = process.env.VNP_HASHSECRET
        const returnUrl = process.env.VNP_RETURN_URL
        const payUrl = process.env.VNP_URL

        const createDate = new Date().toISOString().replace(/[-:.TZ]/g, '').slice(0, 14)

        const params: Record<string, string> = {
            vnp_Version: '2.1.0',
            vnp_Command: 'pay',
            vnp_TmnCode: tmnCode,
            vnp_Locale: 'vn',
            vnp_CurrCode: 'VND',
            vnp_TxnRef: orderId,
            vnp_OrderInfo: `Thanh toan don hang ${orderId}`,
            vnp_OrderType: 'other',
            vnp_Amount: (amount * 100).toString(),
            vnp_ReturnUrl: returnUrl,
            vnp_IpAddr: ip,
            vnp_CreateDate: createDate,
        }

        const sorted = Object.fromEntries(Object.entries(params).sort());
        const signData = qs.stringify(sorted, { encode: false });
        const signature = crypto.createHmac('sha512', secret).update(signData).digest('hex');

        return `${payUrl}?${signData}&vnp_SecureHash=${signature}`;
    }

    validateCallback(query: any): boolean {
        const { vnp_SecureHash, ...rest } = query;
        const secret = this.config.get('VNP_HASHSECRET');

        const sorted = Object.fromEntries(Object.entries(rest).sort());
        const signData = qs.stringify(sorted, { encode: false });
        const hash = crypto.createHmac('sha512', secret).update(signData).digest('hex');

        return hash === vnp_SecureHash;
    }
}