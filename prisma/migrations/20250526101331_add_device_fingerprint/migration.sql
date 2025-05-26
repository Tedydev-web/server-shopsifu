-- AlterTable
ALTER TABLE "Device" ADD COLUMN     "fingerprint" VARCHAR(255);

-- CreateIndex
CREATE INDEX "Device_userId_fingerprint_idx" ON "Device"("userId", "fingerprint");
