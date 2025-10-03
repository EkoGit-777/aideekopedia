import { b as defineEventHandler, p as prisma } from '../../_/nitro.mjs';
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

const index_get = defineEventHandler(async () => {
  return prisma.chatSession.findMany({
    include: { messages: true, user: true }
  });
});

export { index_get as default };
//# sourceMappingURL=index.get.mjs.map
