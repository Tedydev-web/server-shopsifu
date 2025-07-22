-- AlterTable
ALTER TABLE "Discount" ADD COLUMN     "maxDiscountValue" INTEGER,
ALTER COLUMN "maxUsesPerUser" SET DEFAULT 0,
ALTER COLUMN "minOrderValue" SET DEFAULT 0,
ALTER COLUMN "maxUses" SET DEFAULT 0;
