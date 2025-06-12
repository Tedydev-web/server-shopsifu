/*
  Warnings:

  - You are about to drop the column `category` on the `Permission` table. All the data in the column will be lost.

*/
-- DropIndex
DROP INDEX "Permission_category_idx";

-- AlterTable
ALTER TABLE "Permission" DROP COLUMN "category",
ADD COLUMN     "ui_metadata" JSONB;
