/*
  Warnings:

  - Added the required column `name` to the `Category` table without a default value. This is not possible if the table is not empty.

*/
-- AlterTable
ALTER TABLE "Category" ADD COLUMN     "logo" VARCHAR(1000),
ADD COLUMN     "name" VARCHAR(500) NOT NULL;

CREATE UNIQUE INDEX "CategoryTranslation_categoryId_languageId_unique"
ON "CategoryTranslation" ("categoryId", "languageId")
WHERE "deletedAt" IS NULL;-- This is an empty migration.