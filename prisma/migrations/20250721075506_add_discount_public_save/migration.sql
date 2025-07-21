/*
  Warnings:

  - You are about to drop the column `userId` on the `Discount` table. All the data in the column will be lost.

*/
-- DropForeignKey
ALTER TABLE "Discount" DROP CONSTRAINT "Discount_userId_fkey";

-- AlterTable
ALTER TABLE "Discount" DROP COLUMN "userId",
ADD COLUMN     "canSaveBeforeStart" BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN     "isPublic" BOOLEAN NOT NULL DEFAULT true;
