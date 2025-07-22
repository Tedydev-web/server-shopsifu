-- AlterTable
ALTER TABLE "Brand" ADD COLUMN     "discountId" TEXT;

-- AlterTable
ALTER TABLE "Category" ADD COLUMN     "discountId" TEXT;

-- AlterTable
ALTER TABLE "Discount" ADD COLUMN     "userConditions" JSONB;

-- AddForeignKey
ALTER TABLE "Category" ADD CONSTRAINT "Category_discountId_fkey" FOREIGN KEY ("discountId") REFERENCES "Discount"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Brand" ADD CONSTRAINT "Brand_discountId_fkey" FOREIGN KEY ("discountId") REFERENCES "Discount"("id") ON DELETE SET NULL ON UPDATE CASCADE;
