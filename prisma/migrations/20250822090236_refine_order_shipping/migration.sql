/*
  Warnings:

  - The `status` column on the `OrderShipping` table would be dropped and recreated. This will lead to data loss if there is data in the column.

*/
-- CreateEnum
CREATE TYPE "OrderShippingStatus" AS ENUM ('DRAFT', 'ENQUEUED', 'CREATED', 'FAILED');

-- AlterTable
ALTER TABLE "OrderShipping" ADD COLUMN     "attempts" INTEGER NOT NULL DEFAULT 0,
ADD COLUMN     "configFeeId" TEXT,
ADD COLUMN     "extraCostId" TEXT,
ADD COLUMN     "height" INTEGER,
ADD COLUMN     "lastError" TEXT,
ADD COLUMN     "length" INTEGER,
ADD COLUMN     "note" TEXT,
ADD COLUMN     "pickShift" JSONB,
ADD COLUMN     "requiredNote" TEXT,
ADD COLUMN     "weight" INTEGER,
ADD COLUMN     "width" INTEGER,
DROP COLUMN "status",
ADD COLUMN     "status" "OrderShippingStatus";

-- CreateIndex
CREATE INDEX "OrderShipping_status_idx" ON "OrderShipping"("status");
