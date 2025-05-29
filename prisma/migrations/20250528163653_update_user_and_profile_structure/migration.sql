/*
  Warnings:

  - You are about to drop the column `isSecondaryEmailVerified` on the `UserProfile` table. All the data in the column will be lost.
  - You are about to drop the column `secondaryEmail` on the `UserProfile` table. All the data in the column will be lost.
  - You are about to drop the column `secondaryEmailVerifiedAt` on the `UserProfile` table. All the data in the column will be lost.
  - A unique constraint covering the columns `[pendingEmail]` on the table `User` will be added. If there are existing duplicate values, this will fail.

*/
-- DropIndex
DROP INDEX "UserProfile_secondaryEmail_key";

-- AlterTable
ALTER TABLE "User" ADD COLUMN     "emailVerificationSentAt" TIMESTAMP(3),
ADD COLUMN     "emailVerificationToken" VARCHAR(255),
ADD COLUMN     "emailVerificationTokenExpiresAt" TIMESTAMP(3),
ADD COLUMN     "isEmailVerified" BOOLEAN NOT NULL DEFAULT true,
ADD COLUMN     "pendingEmail" VARCHAR(255);

-- AlterTable
ALTER TABLE "UserProfile" DROP COLUMN "isSecondaryEmailVerified",
DROP COLUMN "secondaryEmail",
DROP COLUMN "secondaryEmailVerifiedAt";

-- CreateIndex
CREATE UNIQUE INDEX "User_pendingEmail_key" ON "User"("pendingEmail");
