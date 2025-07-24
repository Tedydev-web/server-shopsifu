-- CreateEnum
CREATE TYPE "VoucherType" AS ENUM ('SHOP', 'PRODUCT');

-- CreateEnum
CREATE TYPE "DisplayType" AS ENUM ('PUBLIC', 'PRIVATE');

-- AlterTable
ALTER TABLE "Discount" ADD COLUMN     "displayType" "DisplayType" NOT NULL DEFAULT 'PUBLIC',
ADD COLUMN     "voucherType" "VoucherType" NOT NULL DEFAULT 'SHOP';
