-- AlterTable
ALTER TABLE "Permission" ADD COLUMN     "conditions" JSONB,
ALTER COLUMN "category" DROP NOT NULL,
ALTER COLUMN "subject" SET DATA TYPE VARCHAR(255);

-- AlterTable
ALTER TABLE "Role" ADD COLUMN     "isSuperAdmin" BOOLEAN NOT NULL DEFAULT false;

-- CreateIndex
CREATE INDEX "Permission_subject_action_idx" ON "Permission"("subject", "action");
