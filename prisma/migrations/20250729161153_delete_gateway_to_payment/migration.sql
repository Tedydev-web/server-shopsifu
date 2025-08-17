/*
  Warnings:

  - You are about to drop the column `gateway` on the `Payment` table. All the data in the column will be lost.

*/
-- DropIndex
DROP INDEX "Payment_gateway_idx";

-- AlterTable
ALTER TABLE "Payment" DROP COLUMN "gateway";
