/*
  Warnings:

  - You are about to drop the column `canSaveBeforeStart` on the `Discount` table. All the data in the column will be lost.
  - You are about to drop the column `userConditions` on the `Discount` table. All the data in the column will be lost.
  - You are about to drop the column `userId` on the `Discount` table. All the data in the column will be lost.
  - You are about to drop the `AppliedDiscount` table. If the table is not empty, all the data it contains will be lost.
  - You are about to drop the `_DiscountToProduct` table. If the table is not empty, all the data it contains will be lost.
  - Added the required column `updatedAt` to the `ProductSKUSnapshot` table without a default value. This is not possible if the table is not empty.

*/
-- DropForeignKey
ALTER TABLE "AppliedDiscount" DROP CONSTRAINT "AppliedDiscount_discountId_fkey";

-- DropForeignKey
ALTER TABLE "AppliedDiscount" DROP CONSTRAINT "AppliedDiscount_orderId_fkey";

-- DropForeignKey
ALTER TABLE "Order" DROP CONSTRAINT "Order_shopId_fkey";

-- DropForeignKey
ALTER TABLE "_DiscountToProduct" DROP CONSTRAINT "_DiscountToProduct_A_fkey";

-- DropForeignKey
ALTER TABLE "_DiscountToProduct" DROP CONSTRAINT "_DiscountToProduct_B_fkey";

-- AlterTable
ALTER TABLE "Discount" DROP COLUMN "canSaveBeforeStart",
DROP COLUMN "userConditions",
DROP COLUMN "userId",
ALTER COLUMN "description" DROP NOT NULL,
ALTER COLUMN "description" SET DEFAULT '',
ALTER COLUMN "description" SET DATA TYPE TEXT;

-- AlterTable
ALTER TABLE "Product" ADD COLUMN     "discountId" TEXT;

-- AlterTable
ALTER TABLE "ProductSKUSnapshot" ADD COLUMN     "updatedAt" TIMESTAMP(3) NOT NULL;

-- DropTable
DROP TABLE "AppliedDiscount";

-- DropTable
DROP TABLE "_DiscountToProduct";

-- CreateTable
CREATE TABLE "DiscountSnapshot" (
    "id" TEXT NOT NULL,
    "name" VARCHAR(500) NOT NULL,
    "description" VARCHAR(1000),
    "type" "DiscountType" NOT NULL,
    "value" INTEGER NOT NULL,
    "code" VARCHAR(100) NOT NULL,
    "maxDiscountValue" INTEGER,
    "discountAmount" INTEGER NOT NULL,
    "minOrderValue" INTEGER NOT NULL,
    "isPublic" BOOLEAN NOT NULL,
    "appliesTo" "DiscountApplyType" NOT NULL,
    "targetInfo" JSONB,
    "discountId" TEXT,
    "orderId" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "DiscountSnapshot_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "DiscountSnapshot_orderId_idx" ON "DiscountSnapshot"("orderId");

-- CreateIndex
CREATE INDEX "DiscountSnapshot_discountId_idx" ON "DiscountSnapshot"("discountId");

-- CreateIndex
CREATE INDEX "ProductSKUSnapshot_orderId_idx" ON "ProductSKUSnapshot"("orderId");

-- AddForeignKey
ALTER TABLE "Product" ADD CONSTRAINT "Product_discountId_fkey" FOREIGN KEY ("discountId") REFERENCES "Discount"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "DiscountSnapshot" ADD CONSTRAINT "DiscountSnapshot_discountId_fkey" FOREIGN KEY ("discountId") REFERENCES "Discount"("id") ON DELETE SET NULL ON UPDATE NO ACTION;

-- AddForeignKey
ALTER TABLE "DiscountSnapshot" ADD CONSTRAINT "DiscountSnapshot_orderId_fkey" FOREIGN KEY ("orderId") REFERENCES "Order"("id") ON DELETE SET NULL ON UPDATE NO ACTION;

-- AddForeignKey
ALTER TABLE "Order" ADD CONSTRAINT "Order_shopId_fkey" FOREIGN KEY ("shopId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE NO ACTION;
