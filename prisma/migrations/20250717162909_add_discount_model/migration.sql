-- CreateEnum
CREATE TYPE "DiscountType" AS ENUM ('FIX_AMOUNT', 'PERCENTAGE');

-- CreateEnum
CREATE TYPE "DiscountStatus" AS ENUM ('DRAFT', 'INACTIVE', 'ACTIVE');

-- CreateEnum
CREATE TYPE "DiscountApplyType" AS ENUM ('ALL', 'SPECIFIC');

-- CreateTable
CREATE TABLE "Discount" (
    "id" TEXT NOT NULL,
    "name" VARCHAR(500) NOT NULL,
    "description" VARCHAR(1000) NOT NULL,
    "type" "DiscountType" NOT NULL DEFAULT 'FIX_AMOUNT',
    "value" INTEGER NOT NULL,
    "code" VARCHAR(100) NOT NULL,
    "startDate" TIMESTAMP(3) NOT NULL,
    "endDate" TIMESTAMP(3) NOT NULL,
    "maxUsed" INTEGER NOT NULL,
    "usesCount" INTEGER NOT NULL DEFAULT 0,
    "usersUsed" TEXT[],
    "maxUsesPerUser" INTEGER NOT NULL,
    "minOrderValue" INTEGER NOT NULL,
    "shopId" TEXT NOT NULL,
    "status" "DiscountStatus" NOT NULL DEFAULT 'DRAFT',
    "appliesTo" "DiscountApplyType" NOT NULL DEFAULT 'ALL',
    "productIds" TEXT[],
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Discount_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "Discount_code_key" ON "Discount"("code");

-- AddForeignKey
ALTER TABLE "Discount" ADD CONSTRAINT "Discount_shopId_fkey" FOREIGN KEY ("shopId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE NO ACTION;
