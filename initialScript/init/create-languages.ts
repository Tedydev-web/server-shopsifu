import { PrismaClient } from '@prisma/client'

const prisma = new PrismaClient()

/**
 * Tạo các ngôn ngữ cơ bản nếu chưa tồn tại
 */
async function createLanguages(): Promise<void> {
  console.log('🔤 Bắt đầu tạo ngôn ngữ...')
  
  const languages = [
    {
      id: 'vi',
      name: 'Tiếng Việt'
    },
    {
      id: 'en', 
      name: 'English'
    }
  ]

  for (const language of languages) {
    const existingLanguage = await prisma.language.findUnique({
      where: { id: language.id }
    })

    if (!existingLanguage) {
      await prisma.language.create({
        data: {
          id: language.id,
          name: language.name
        }
      })
      console.log(`✅ Đã tạo ngôn ngữ: ${language.name} (${language.id})`)
    } else {
      console.log(`ℹ️  Ngôn ngữ đã tồn tại: ${language.name} (${language.id})`)
    }
  }

  console.log('✅ Hoàn thành tạo ngôn ngữ!')
}

async function main(): Promise<void> {
  try {
    await prisma.$connect()
    await createLanguages()
  } catch (error) {
    console.error('❌ Lỗi khi tạo ngôn ngữ:', error)
    throw error
  } finally {
    await prisma.$disconnect()
  }
}

if (require.main === module) {
  main()
    .then(() => {
      console.log('🎉 Script tạo ngôn ngữ hoàn thành!')
      process.exit(0)
    })
    .catch((error) => {
      console.error('💥 Script tạo ngôn ngữ thất bại:', error)
      process.exit(1)
    })
}

export { createLanguages }






