import { _ as _sfc_main$1 } from './text-area-Dh21SB57.mjs';
import { defineComponent, ref, mergeProps, unref, isRef, useSSRContext } from 'vue';
import { ssrRenderAttrs, ssrRenderAttr, ssrRenderComponent } from 'vue/server-renderer';
import { _ as _imports_0 } from './virtual_public-IWZl7zz2.mjs';
import { u as useSessionStore } from './sessions-Ch2qXTsx.mjs';
import { a as useRouter } from './server.mjs';
import '../_/nitro.mjs';
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
import 'pinia';
import 'vue-router';

const _sfc_main = /* @__PURE__ */ defineComponent({
  __name: "index",
  __ssrInlineRender: true,
  setup(__props) {
    const query = ref("");
    const sessionStore = useSessionStore();
    const router = useRouter();
    const startChat = async () => {
      if (!query.value.trim()) return;
      await sessionStore.setSessions({
        userId: "current-user-id",
        // replace with actual logged-in userId
        title: query.value
        // use first query as session title
      });
      console.log("Session started with title:", query.value);
      const newSession = sessionStore.sessions.at(-1);
      if (newSession) {
        router.push({
          path: `/${newSession.id}`,
          query: { first: query.value }
        });
      }
      query.value = "";
    };
    return (_ctx, _push, _parent, _attrs) => {
      const _component_input_text_area = _sfc_main$1;
      _push(`<div${ssrRenderAttrs(mergeProps({ class: "relative box-border flex-col flex w-full justify-center px-24 md:px-128 h-full space-y-12 items-center" }, _attrs))}><div class="space-y-8 flex flex-col items-center justify-center h-full md:h-fit"><img${ssrRenderAttr("src", _imports_0)} alt="logo" class="w-80 md:w-88 lg:w-104 xl:w-128"><div class="text20 text-yellow">What can I help you today?</div></div><div class="py-24 w-full">`);
      _push(ssrRenderComponent(_component_input_text_area, {
        class: "w-full bottom-24 px-8 py-4 text12 rounded-12",
        placeholder: "Ask me anything",
        modelValue: unref(query),
        "onUpdate:modelValue": ($event) => isRef(query) ? query.value = $event : null,
        onEnter: startChat
      }, null, _parent));
      _push(`</div></div>`);
    };
  }
});
const _sfc_setup = _sfc_main.setup;
_sfc_main.setup = (props, ctx) => {
  const ssrContext = useSSRContext();
  (ssrContext.modules || (ssrContext.modules = /* @__PURE__ */ new Set())).add("pages/index.vue");
  return _sfc_setup ? _sfc_setup(props, ctx) : void 0;
};

export { _sfc_main as default };
//# sourceMappingURL=index-D_KIimsx.mjs.map
