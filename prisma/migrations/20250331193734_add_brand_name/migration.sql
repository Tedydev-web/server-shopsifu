/*
  Warnings:

  - Added the required column `name` to the `Brand` table without a default value. This is not possible if the table is not empty.

*/
-- AlterTable
ALTER TABLE "Brand" ADD COLUMN     "name" VARCHAR(500) NOT NULL;

CREATE UNIQUE INDEX "BrandTranslation_brandId_languageId_unique"
ON "BrandTranslation" ("brandId", "languageId")
WHERE "deletedAt" IS NULL;-- This is an empty migration.