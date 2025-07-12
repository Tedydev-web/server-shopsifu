/*
  Warnings:

  - You are about to drop the column `content` on the `Permission` table. All the data in the column will be lost.
  - Added the required column `description` to the `Permission` table without a default value. This is not possible if the table is not empty.

*/
-- AlterTable
ALTER TABLE "Permission" RENAME COLUMN "content" TO "description";
