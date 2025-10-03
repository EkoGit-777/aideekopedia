import { createGoogleGenerativeAI } from '@ai-sdk/google'
import { generateText } from 'ai'

const googleModel = createGoogleGenerativeAI({
  apiKey: useRuntimeConfig().openaiApiKey,
})

export async function askGemini(prompt: string) {
  const { text } = await generateText({
    model: googleModel('gemini-1.5-pro'),
    prompt
  })
  console.log('Gemini reply:', text)
  return text
}