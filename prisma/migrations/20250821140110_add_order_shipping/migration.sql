-- CreateTable
CREATE TABLE "OrderShipping" (
    "id" TEXT NOT NULL,
    "orderId" TEXT NOT NULL,
    "orderCode" TEXT,
    "serviceId" INTEGER,
    "serviceTypeId" INTEGER,
    "shippingFee" INTEGER,
    "codAmount" INTEGER,
    "expectedDeliveryTime" TIMESTAMP(3),
    "trackingUrl" TEXT,
    "status" TEXT,
    "fromAddress" TEXT,
    "fromName" TEXT,
    "fromPhone" TEXT,
    "fromProvinceName" TEXT,
    "fromDistrictName" TEXT,
    "fromWardName" TEXT,
    "fromDistrictId" INTEGER,
    "fromWardCode" TEXT,
    "toAddress" TEXT,
    "toName" TEXT,
    "toPhone" TEXT,
    "toDistrictId" INTEGER,
    "toWardCode" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastUpdatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "OrderShipping_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "OrderShipping_orderId_key" ON "OrderShipping"("orderId");

-- CreateIndex
CREATE UNIQUE INDEX "OrderShipping_orderCode_key" ON "OrderShipping"("orderCode");

-- CreateIndex
CREATE INDEX "OrderShipping_status_idx" ON "OrderShipping"("status");

-- AddForeignKey
ALTER TABLE "OrderShipping" ADD CONSTRAINT "OrderShipping_orderId_fkey" FOREIGN KEY ("orderId") REFERENCES "Order"("id") ON DELETE CASCADE ON UPDATE NO ACTION;
