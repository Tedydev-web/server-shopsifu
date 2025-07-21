/*
  Warnings:

  - You are about to drop the column `shopId` on the `Discount` table. All the data in the column will be lost.

*/
-- DropForeignKey
ALTER TABLE "Discount" DROP CONSTRAINT "Discount_shopId_fkey";

-- AlterTable
ALTER TABLE "Discount" DROP COLUMN "shopId",
ADD COLUMN     "userId" TEXT;
