import { PrismaService } from 'src/shared/services/prisma.service'

const prisma = new PrismaService()

const addBrands = async () => {
  const brands = Array(10000)
    .fill(0)
    .map((_, index) => ({
      logo: `Logo ${index}`,
    }))
  try {
    const { count } = await prisma.brand.createMany({
      data: brands,
    })
    console.log(`Added ${count} brands`)
  } catch (error) {
    console.log(error)
  }
}

addBrands()
