import { streamText, UIMessage, convertToModelMessages } from 'ai';
import { createGoogleGenerativeAI } from '@ai-sdk/google';

export default defineLazyEventHandler(async () => {
  const apiKey = useRuntimeConfig().googleGeminiApiKey;
  if (!apiKey) throw new Error('Missing OpenAI API key');
  const googleModel = createGoogleGenerativeAI({
    apiKey: useRuntimeConfig().openaiApiKey,
  })

  return defineEventHandler(async (event: any) => {
    const { messages }: { messages: UIMessage[] } = await readBody(event);

    const result = streamText({
      model: googleModel('gemini-2.5-flash'),
      messages: convertToModelMessages(messages),
    });
    console.log('Gemini response: ' + JSON.stringify(result));

    return result.toUIMessageStreamResponse();
  });
});