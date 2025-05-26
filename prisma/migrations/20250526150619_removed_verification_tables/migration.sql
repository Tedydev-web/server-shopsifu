/*
  Warnings:

  - You are about to drop the `VerificationCode` table. If the table is not empty, all the data it contains will be lost.
  - You are about to drop the `VerificationToken` table. If the table is not empty, all the data it contains will be lost.

*/
-- DropForeignKey
ALTER TABLE "VerificationToken" DROP CONSTRAINT "VerificationToken_deviceId_fkey";

-- DropForeignKey
ALTER TABLE "VerificationToken" DROP CONSTRAINT "VerificationToken_userId_fkey";

-- AlterTable
ALTER TABLE "User" ALTER COLUMN "status" SET DEFAULT 'ACTIVE';

-- DropTable
DROP TABLE "VerificationCode";

-- DropTable
DROP TABLE "VerificationToken";
