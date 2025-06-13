/*
  Warnings:

  - The values [AUTHENTICATOR_APP] on the enum `TwoFactorMethodType` will be removed. If these variants are still used in the database, this will fail.

*/
-- AlterEnum
BEGIN;
CREATE TYPE "TwoFactorMethodType_new" AS ENUM ('EMAIL', 'TOTP', 'RECOVERY_CODE');
ALTER TABLE "users" ALTER COLUMN "two_factor_method" TYPE "TwoFactorMethodType_new" USING ("two_factor_method"::text::"TwoFactorMethodType_new");
ALTER TYPE "TwoFactorMethodType" RENAME TO "TwoFactorMethodType_old";
ALTER TYPE "TwoFactorMethodType_new" RENAME TO "TwoFactorMethodType";
DROP TYPE "TwoFactorMethodType_old";
COMMIT;

-- AlterTable
ALTER TABLE "devices" ADD COLUMN     "browser" VARCHAR(100),
ADD COLUMN     "browser_version" VARCHAR(50),
ADD COLUMN     "device_model" VARCHAR(100),
ADD COLUMN     "device_type" VARCHAR(50),
ADD COLUMN     "device_vendor" VARCHAR(100),
ADD COLUMN     "os" VARCHAR(100),
ADD COLUMN     "os_version" VARCHAR(50);

-- CreateIndex
CREATE INDEX "devices_user_id_browser_os_idx" ON "devices"("user_id", "browser", "os");
