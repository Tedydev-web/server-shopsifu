/*
  Warnings:

  - You are about to drop the column `appliesTo` on the `DiscountSnapshot` table. All the data in the column will be lost.
  - You are about to drop the column `isPublic` on the `DiscountSnapshot` table. All the data in the column will be lost.
  - You are about to drop the column `type` on the `DiscountSnapshot` table. All the data in the column will be lost.
  - Added the required column `discountApplyType` to the `DiscountSnapshot` table without a default value. This is not possible if the table is not empty.
  - Added the required column `discountType` to the `DiscountSnapshot` table without a default value. This is not possible if the table is not empty.
  - Added the required column `displayType` to the `DiscountSnapshot` table without a default value. This is not possible if the table is not empty.
  - Added the required column `isPlatform` to the `DiscountSnapshot` table without a default value. This is not possible if the table is not empty.
  - Added the required column `voucherType` to the `DiscountSnapshot` table without a default value. This is not possible if the table is not empty.

*/
-- AlterTable
ALTER TABLE "DiscountSnapshot" DROP COLUMN "appliesTo",
DROP COLUMN "isPublic",
DROP COLUMN "type",
ADD COLUMN     "discountApplyType" "DiscountApplyType" NOT NULL,
ADD COLUMN     "discountType" "DiscountType" NOT NULL,
ADD COLUMN     "displayType" "DisplayType" NOT NULL,
ADD COLUMN     "isPlatform" BOOLEAN NOT NULL,
ADD COLUMN     "voucherType" "VoucherType" NOT NULL;
