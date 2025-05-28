/*
  Warnings:

  - You are about to drop the column `avatar` on the `User` table. All the data in the column will be lost.
  - You are about to drop the column `name` on the `User` table. All the data in the column will be lost.
  - You are about to drop the column `phoneNumber` on the `User` table. All the data in the column will be lost.

*/
-- AlterEnum
-- This migration adds more than one value to an enum.
-- With PostgreSQL versions 11 and earlier, this is not possible
-- in a single migration. This can be worked around by creating
-- multiple migrations, each migration adding only one value to
-- the enum.


ALTER TYPE "VerificationCodeType" ADD VALUE 'VERIFY_SECONDARY_EMAIL';
ALTER TYPE "VerificationCodeType" ADD VALUE 'VERIFY_PHONE_NUMBER';

-- AlterTable
ALTER TABLE "User" DROP COLUMN "avatar",
DROP COLUMN "name",
DROP COLUMN "phoneNumber";

-- CreateTable
CREATE TABLE "UserProfile" (
    "id" SERIAL NOT NULL,
    "userId" INTEGER NOT NULL,
    "firstName" VARCHAR(255),
    "lastName" VARCHAR(255),
    "username" VARCHAR(100),
    "avatar" VARCHAR(1000),
    "bio" TEXT,
    "phoneNumber" VARCHAR(50),
    "isPhoneNumberVerified" BOOLEAN NOT NULL DEFAULT false,
    "phoneNumberVerifiedAt" TIMESTAMP(3),
    "countryCode" VARCHAR(10),
    "secondaryEmail" VARCHAR(255),
    "isSecondaryEmailVerified" BOOLEAN NOT NULL DEFAULT false,
    "secondaryEmailVerifiedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "UserProfile_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "UserProfile_userId_key" ON "UserProfile"("userId");

-- CreateIndex
CREATE UNIQUE INDEX "UserProfile_username_key" ON "UserProfile"("username");

-- CreateIndex
CREATE UNIQUE INDEX "UserProfile_phoneNumber_key" ON "UserProfile"("phoneNumber");

-- CreateIndex
CREATE UNIQUE INDEX "UserProfile_secondaryEmail_key" ON "UserProfile"("secondaryEmail");

-- CreateIndex
CREATE INDEX "UserProfile_userId_idx" ON "UserProfile"("userId");

-- AddForeignKey
ALTER TABLE "UserProfile" ADD CONSTRAINT "UserProfile_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;
