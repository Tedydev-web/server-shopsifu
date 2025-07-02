/*
  Warnings:

  - You are about to drop the column `revoked_all_sessions_before` on the `User` table. All the data in the column will be lost.
  - A unique constraint covering the columns `[name]` on the table `Role` will be added. If there are existing duplicate values, this will fail.
  - Added the required column `name` to the `Brand` table without a default value. This is not possible if the table is not empty.

*/
-- DropIndex
DROP INDEX "User_email_key";

-- DropIndex
DROP INDEX "User_totpSecret_key";

-- AlterTable
ALTER TABLE "Brand" ADD COLUMN     "name" VARCHAR(500) NOT NULL;

-- AlterTable
ALTER TABLE "Role" ALTER COLUMN "name" SET DEFAULT '';

-- AlterTable
ALTER TABLE "User" DROP COLUMN "revoked_all_sessions_before";

-- CreateIndex
CREATE UNIQUE INDEX "Role_name_key" ON "Role"("name");

CREATE UNIQUE INDEX "BrandTranslation_brandId_languageId_unique"
ON "BrandTranslation" ("brandId", "languageId")
WHERE "deletedAt" IS NULL;