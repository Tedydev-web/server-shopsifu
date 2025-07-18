/*
  Warnings:

  - You are about to drop the column `maxUsed` on the `Discount` table. All the data in the column will be lost.
  - You are about to drop the column `productIds` on the `Discount` table. All the data in the column will be lost.
  - You are about to drop the column `discountId` on the `Order` table. All the data in the column will be lost.
  - Added the required column `maxUses` to the `Discount` table without a default value. This is not possible if the table is not empty.
  - Added the required column `userId` to the `Discount` table without a default value. This is not possible if the table is not empty.

*/
-- DropForeignKey
ALTER TABLE "Discount" DROP CONSTRAINT "Discount_shopId_fkey";

-- DropForeignKey
ALTER TABLE "Order" DROP CONSTRAINT "Order_discountId_fkey";

-- DropForeignKey
ALTER TABLE "Order" DROP CONSTRAINT "Order_shopId_fkey";

-- DropIndex
DROP INDEX "Discount_appliesTo_shopId_idx";

-- DropIndex
DROP INDEX "Discount_code_deletedAt_idx";

-- DropIndex
DROP INDEX "Discount_shopId_deletedAt_idx";

-- DropIndex
DROP INDEX "Order_discountId_idx";

-- AlterTable
ALTER TABLE "Discount" DROP COLUMN "maxUsed",
DROP COLUMN "productIds",
ADD COLUMN     "maxUses" INTEGER NOT NULL,
ADD COLUMN     "userId" TEXT NOT NULL,
ALTER COLUMN "shopId" DROP NOT NULL;

-- AlterTable
ALTER TABLE "Order" DROP COLUMN "discountId";

-- AlterTable
ALTER TABLE "Product" ADD COLUMN     "discountId" TEXT;

-- AddForeignKey
ALTER TABLE "Product" ADD CONSTRAINT "Product_discountId_fkey" FOREIGN KEY ("discountId") REFERENCES "Discount"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Discount" ADD CONSTRAINT "Discount_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE NO ACTION ON UPDATE NO ACTION;

-- AddForeignKey
ALTER TABLE "Discount" ADD CONSTRAINT "Discount_shopId_fkey" FOREIGN KEY ("shopId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE NO ACTION;

-- AddForeignKey
ALTER TABLE "Order" ADD CONSTRAINT "Order_shopId_fkey" FOREIGN KEY ("shopId") REFERENCES "User"("id") ON DELETE NO ACTION ON UPDATE NO ACTION;
