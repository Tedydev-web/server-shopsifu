/*
  Warnings:

  - You are about to drop the column `ui_metadata` on the `permissions` table. All the data in the column will be lost.

*/
-- AlterTable
ALTER TABLE "permissions" DROP COLUMN "ui_metadata";
