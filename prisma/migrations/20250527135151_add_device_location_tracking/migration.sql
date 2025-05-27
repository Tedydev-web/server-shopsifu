-- AlterTable
ALTER TABLE "Device" ADD COLUMN     "lastKnownCity" VARCHAR(100),
ADD COLUMN     "lastKnownCountry" VARCHAR(100),
ADD COLUMN     "lastKnownIp" VARCHAR(45),
ADD COLUMN     "lastNotificationSentAt" TIMESTAMP(3);
