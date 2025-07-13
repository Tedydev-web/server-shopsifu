-- DropForeignKey
ALTER TABLE "CartItem" DROP CONSTRAINT "CartItem_skuId_fkey";

-- CreateIndex
CREATE INDEX "CartItem_userId_idx" ON "CartItem"("userId");

-- CreateIndex
CREATE INDEX "SKU_productId_idx" ON "SKU"("productId");

-- AddForeignKey
ALTER TABLE "CartItem" ADD CONSTRAINT "CartItem_skuId_fkey" FOREIGN KEY ("skuId") REFERENCES "SKU"("id") ON DELETE CASCADE ON UPDATE NO ACTION;
