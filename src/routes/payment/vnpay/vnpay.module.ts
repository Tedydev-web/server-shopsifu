import { Module } from "@nestjs/common";
import { VnpayService } from "./vnpay.service";

@Module({
    providers: [VnpayService],
    exports: [VnpayService]
})
export class VnpayModule{}