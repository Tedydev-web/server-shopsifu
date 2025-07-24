/*
  Warnings:

  - You are about to drop the column `appliesTo` on the `Discount` table. All the data in the column will be lost.
  - You are about to drop the column `isPublic` on the `Discount` table. All the data in the column will be lost.
  - You are about to drop the column `status` on the `Discount` table. All the data in the column will be lost.
  - You are about to drop the column `type` on the `Discount` table. All the data in the column will be lost.

*/
-- DropIndex
DROP INDEX "Discount_status_deletedAt_idx";

-- AlterTable
ALTER TABLE "Discount" DROP COLUMN "appliesTo",
DROP COLUMN "isPublic",
DROP COLUMN "status",
DROP COLUMN "type",
ADD COLUMN     "discountApplyType" "DiscountApplyType" NOT NULL DEFAULT 'ALL',
ADD COLUMN     "discountStatus" "DiscountStatus" NOT NULL DEFAULT 'DRAFT',
ADD COLUMN     "discountType" "DiscountType" NOT NULL DEFAULT 'FIX_AMOUNT';

-- CreateIndex
CREATE INDEX "Discount_discountStatus_deletedAt_idx" ON "Discount"("discountStatus", "deletedAt");
