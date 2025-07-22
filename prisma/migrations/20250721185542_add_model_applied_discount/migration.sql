/*
  Warnings:

  - You are about to drop the column `discountAmount` on the `Order` table. All the data in the column will be lost.
  - You are about to drop the column `discountId` on the `Order` table. All the data in the column will be lost.

*/
-- DropForeignKey
ALTER TABLE "Order" DROP CONSTRAINT "Order_discountId_fkey";

-- AlterTable
ALTER TABLE "Order" DROP COLUMN "discountAmount",
DROP COLUMN "discountId";

-- CreateTable
CREATE TABLE "AppliedDiscount" (
    "id" TEXT NOT NULL,
    "orderId" TEXT NOT NULL,
    "discountId" TEXT NOT NULL,
    "code" TEXT NOT NULL,
    "type" "DiscountType" NOT NULL,
    "value" INTEGER NOT NULL,
    "discountAmount" INTEGER NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "AppliedDiscount_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "AppliedDiscount_orderId_idx" ON "AppliedDiscount"("orderId");

-- CreateIndex
CREATE INDEX "AppliedDiscount_discountId_idx" ON "AppliedDiscount"("discountId");

-- AddForeignKey
ALTER TABLE "AppliedDiscount" ADD CONSTRAINT "AppliedDiscount_orderId_fkey" FOREIGN KEY ("orderId") REFERENCES "Order"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AppliedDiscount" ADD CONSTRAINT "AppliedDiscount_discountId_fkey" FOREIGN KEY ("discountId") REFERENCES "Discount"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
