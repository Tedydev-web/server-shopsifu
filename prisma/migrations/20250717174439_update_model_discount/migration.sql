-- AlterEnum
ALTER TYPE "DiscountStatus" ADD VALUE 'EXPIRED';

-- AlterTable
ALTER TABLE "Discount" ADD COLUMN     "createdById" TEXT,
ADD COLUMN     "deletedAt" TIMESTAMP(3),
ADD COLUMN     "deletedById" TEXT,
ADD COLUMN     "updatedById" TEXT;

-- AlterTable
ALTER TABLE "Order" ADD COLUMN     "discountId" TEXT;

-- CreateIndex
CREATE INDEX "Discount_deletedAt_idx" ON "Discount"("deletedAt");

-- CreateIndex
CREATE INDEX "Discount_shopId_deletedAt_idx" ON "Discount"("shopId", "deletedAt");

-- CreateIndex
CREATE INDEX "Discount_status_deletedAt_idx" ON "Discount"("status", "deletedAt");

-- CreateIndex
CREATE INDEX "Discount_startDate_endDate_idx" ON "Discount"("startDate", "endDate");

-- CreateIndex
CREATE INDEX "Discount_code_deletedAt_idx" ON "Discount"("code", "deletedAt");

-- CreateIndex
CREATE INDEX "Discount_appliesTo_shopId_idx" ON "Discount"("appliesTo", "shopId");

-- CreateIndex
CREATE INDEX "Order_discountId_idx" ON "Order"("discountId");

-- AddForeignKey
ALTER TABLE "Discount" ADD CONSTRAINT "Discount_createdById_fkey" FOREIGN KEY ("createdById") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE NO ACTION;

-- AddForeignKey
ALTER TABLE "Discount" ADD CONSTRAINT "Discount_updatedById_fkey" FOREIGN KEY ("updatedById") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE NO ACTION;

-- AddForeignKey
ALTER TABLE "Discount" ADD CONSTRAINT "Discount_deletedById_fkey" FOREIGN KEY ("deletedById") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE NO ACTION;

-- AddForeignKey
ALTER TABLE "Order" ADD CONSTRAINT "Order_discountId_fkey" FOREIGN KEY ("discountId") REFERENCES "Discount"("id") ON DELETE SET NULL ON UPDATE NO ACTION;
