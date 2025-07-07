/*
  Warnings:

  - You are about to drop the column `browser` on the `Device` table. All the data in the column will be lost.
  - You are about to drop the column `browserVersion` on the `Device` table. All the data in the column will be lost.
  - You are about to drop the column `deviceModel` on the `Device` table. All the data in the column will be lost.
  - You are about to drop the column `deviceType` on the `Device` table. All the data in the column will be lost.
  - You are about to drop the column `deviceVendor` on the `Device` table. All the data in the column will be lost.
  - You are about to drop the column `fingerprint` on the `Device` table. All the data in the column will be lost.
  - You are about to drop the column `isTrusted` on the `Device` table. All the data in the column will be lost.
  - You are about to drop the column `lastNotificationSentAt` on the `Device` table. All the data in the column will be lost.
  - You are about to drop the column `name` on the `Device` table. All the data in the column will be lost.
  - You are about to drop the column `os` on the `Device` table. All the data in the column will be lost.
  - You are about to drop the column `osVersion` on the `Device` table. All the data in the column will be lost.
  - You are about to drop the column `trustExpiresAt` on the `Device` table. All the data in the column will be lost.
  - You are about to drop the column `updatedAt` on the `Device` table. All the data in the column will be lost.
  - You are about to drop the `sessions` table. If the table is not empty, all the data it contains will be lost.

*/
-- DropForeignKey
ALTER TABLE "Device" DROP CONSTRAINT "Device_userId_fkey";

-- DropForeignKey
ALTER TABLE "sessions" DROP CONSTRAINT "sessions_deviceId_fkey";

-- DropForeignKey
ALTER TABLE "sessions" DROP CONSTRAINT "sessions_userId_fkey";

-- DropIndex
DROP INDEX "Device_fingerprint_key";

-- AlterTable
ALTER TABLE "Device" DROP COLUMN "browser",
DROP COLUMN "browserVersion",
DROP COLUMN "deviceModel",
DROP COLUMN "deviceType",
DROP COLUMN "deviceVendor",
DROP COLUMN "fingerprint",
DROP COLUMN "isTrusted",
DROP COLUMN "lastNotificationSentAt",
DROP COLUMN "name",
DROP COLUMN "os",
DROP COLUMN "osVersion",
DROP COLUMN "trustExpiresAt",
DROP COLUMN "updatedAt",
ALTER COLUMN "lastActive" DROP DEFAULT;

-- DropTable
DROP TABLE "sessions";

-- CreateTable
CREATE TABLE "RefreshToken" (
    "token" VARCHAR(1000) NOT NULL,
    "userId" INTEGER NOT NULL,
    "deviceId" INTEGER NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- CreateIndex
CREATE UNIQUE INDEX "RefreshToken_token_key" ON "RefreshToken"("token");

-- CreateIndex
CREATE INDEX "RefreshToken_expiresAt_idx" ON "RefreshToken"("expiresAt");

-- AddForeignKey
ALTER TABLE "RefreshToken" ADD CONSTRAINT "RefreshToken_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE NO ACTION;

-- AddForeignKey
ALTER TABLE "RefreshToken" ADD CONSTRAINT "RefreshToken_deviceId_fkey" FOREIGN KEY ("deviceId") REFERENCES "Device"("id") ON DELETE CASCADE ON UPDATE NO ACTION;

-- AddForeignKey
ALTER TABLE "Device" ADD CONSTRAINT "Device_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE NO ACTION;
