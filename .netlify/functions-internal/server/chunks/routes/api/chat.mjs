import { d as defineLazyEventHandler, a as useRuntimeConfig, b as defineEventHandler, r as readBody } from '../../_/nitro.mjs';
import { streamText, convertToModelMessages } from 'ai';
import { createGoogleGenerativeAI } from '@ai-sdk/google';
import 'node:os';
import 'node:tty';
import 'node:fs';
import 'node:path';
import 'node:crypto';
import 'node:child_process';
import 'node:fs/promises';
import 'node:util';
import 'node:process';
import 'node:async_hooks';
import 'node:events';
import 'path';
import 'fs';
import 'node:http';
import 'node:https';
import 'node:buffer';
import '@logto/node';
import '@silverhand/essentials';

const chat = defineLazyEventHandler(async () => {
  const apiKey = useRuntimeConfig().googleGeminiApiKey;
  if (!apiKey) throw new Error("Missing OpenAI API key");
  const googleModel = createGoogleGenerativeAI({
    apiKey: useRuntimeConfig().openaiApiKey
  });
  return defineEventHandler(async (event) => {
    const { messages } = await readBody(event);
    const result = streamText({
      model: googleModel("gemini-2.5-flash"),
      messages: convertToModelMessages(messages)
    });
    console.log("Gemini response: " + JSON.stringify(result));
    return result.toUIMessageStreamResponse();
  });
});

export { chat as default };
//# sourceMappingURL=chat.mjs.map
